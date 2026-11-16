"""Playbook 3 - S3 exfiltration / exposure. Runs as the app-side remediation role.

contain:
  1. turn all four Block Public Access settings back on
  2. delete the bucket policy (the original is saved in pre_containment.json)
  3. reset the ACL to private, only if ACLs are enabled (BucketOwnerEnforced disables them)
eradicate:
  1. apply a quarantine policy: explicit deny for everyone except the remediation,
     auditor and Terraform deployer principals (without the deployer, terraform
     destroy can no longer remove the bucket)
  2. make sure versioning is on (nothing silently overwritten during the investigation)
  3. tag QUARANTINED (merged with existing tags: PutBucketTagging replaces all tags)
  4. optional chaining: if the caller was an argus-sim-* IAM user, start the IAM
     playbook for it - fixing the bucket does not stop the person

Env: REMEDIATION_ROLE_ARN, QUARANTINE_EXEMPT_PRINCIPAL_ARNS (comma-separated),
     IAM_STATE_MACHINE_ARN (optional)
"""

from __future__ import annotations

import json
import logging
import os

from botocore.exceptions import ClientError

from argus_shared import aws_utils as au
from argus_shared.constants import (
    INCIDENT_TAG_KEY,
    QUARANTINE_TIME_TAG_KEY,
    QUARANTINED,
    SIM_NAME_PREFIX,
    STATUS_TAG_KEY,
)
from argus_shared.phase import PhaseRecorder

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, _context):
    envelope = event["envelope"]
    session = au.assume_role(os.environ["REMEDIATION_ROLE_ARN"], envelope["incident_key"])
    s3 = au.client("s3", session)
    phase = event["phase"]
    if phase == "contain":
        return contain(s3, envelope, event.get("evidence", {}))
    if phase == "eradicate":
        # Chaining uses this function's own role (states:StartExecution), not the remediation role.
        return eradicate(s3, au.client("stepfunctions"), envelope)
    raise ValueError(f"unknown phase {phase!r}")


def contain(s3, envelope, evidence):
    rec = PhaseRecorder("contain")
    bucket = envelope["target"]["name"]
    summary = evidence.get("summary") or {}

    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    rec.record("s3:PutBucketPublicAccessBlock", bucket, detail="all four settings on")

    s3.delete_bucket_policy(Bucket=bucket)
    rec.record("s3:DeleteBucketPolicy", bucket, detail={"had_policy": summary.get("had_policy")})

    if summary.get("acls_enabled", True):
        s3.put_bucket_acl(Bucket=bucket, ACL="private")
        rec.record("s3:PutBucketAcl", bucket, detail="private")
    else:
        rec.record("s3:PutBucketAcl", bucket, "skipped", "ACLs disabled (BucketOwnerEnforced)")
    return rec.result()


def quarantine_policy(bucket: str, exempt_arns: list[str]) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ArgusQuarantine",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"ArnNotLike": {"aws:PrincipalArn": exempt_arns}},
        }],
    })


def eradicate(s3, sfn, envelope):
    rec = PhaseRecorder("eradicate")
    bucket = envelope["target"]["name"]
    exempt = [a.strip() for a in os.environ["QUARANTINE_EXEMPT_PRINCIPAL_ARNS"].split(",") if a.strip()]
    if not exempt:
        raise ValueError("QUARANTINE_EXEMPT_PRINCIPAL_ARNS is empty; refusing to lock everyone out")

    s3.put_bucket_policy(Bucket=bucket, Policy=quarantine_policy(bucket, exempt))
    rec.record("s3:PutBucketPolicy", bucket, detail={"quarantine_exempt": exempt})

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    rec.record("s3:PutBucketVersioning", bucket, detail="Enabled")

    try:
        tags = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
    except ClientError as exc:
        if au.error_code(exc) != "NoSuchTagSet":
            raise
        tags = []
    new = {STATUS_TAG_KEY: QUARANTINED, INCIDENT_TAG_KEY: envelope["incident_key"],
           QUARANTINE_TIME_TAG_KEY: au.now_iso()}
    merged = [t for t in tags if t["Key"] not in new] + [{"Key": k, "Value": v} for k, v in new.items()]
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": merged})
    rec.record("s3:PutBucketTagging", bucket, detail=QUARANTINED)

    chain_to_iam(sfn, envelope, rec)
    return rec.result()


def chain_to_iam(sfn, envelope, rec):
    actor = envelope.get("actor") or {}
    user = actor.get("user_name")
    sm_arn = os.environ.get("IAM_STATE_MACHINE_ARN")
    if not user or not sm_arn:
        return
    if not user.startswith(SIM_NAME_PREFIX):
        rec.record("states:StartExecution", user, "skipped", "caller is not an argus-sim-* user; manual action needed")
        return

    # Same shape as the EventBridge input transformer output, with a derived finding ID
    # (its own idempotency key) and chained_from so Finalize skips Security Hub.
    chained_finding_id = f"{envelope['finding_id']}#actor:{user}"
    payload = {
        "finding_id": chained_finding_id,
        "product_arn": envelope["product_arn"],
        "event_id": envelope["event_id"],
        "event_received": envelope["event_received"],
        "finding_type": envelope["finding_type"],
        "severity": envelope["severity"],
        "finding_created": envelope["finding_created"],
        "account": envelope["account"],
        "region": envelope["region"],
        "chained_from": envelope["finding_id"],
        "finding_updated": envelope.get("finding_updated"),
        "resources": [{
            "Type": "AwsIamAccessKey",
            "Id": f"AWS::IAM::AccessKey:{actor.get('access_key_id') or 'unknown'}",
            "Details": {"AwsIamAccessKey": {"PrincipalName": user}},
        }],
    }
    try:
        resp = sfn.start_execution(stateMachineArn=sm_arn, name=f"chain-{envelope['incident_key']}",
                                   input=json.dumps(payload))
        rec.record("states:StartExecution", user, detail={"execution_arn": resp["executionArn"]})
    except ClientError as exc:
        if au.error_code(exc) != "ExecutionAlreadyExists":
            raise
        rec.record("states:StartExecution", user, "skipped", "chained execution already started")
