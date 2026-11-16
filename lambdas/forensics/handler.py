"""PreserveEvidence: record the state of the target BEFORE anything is changed.

Reads through the read-only app-side forensics role; writes evidence with this
function's own role. Writes evidence/{incident_key}/pre_containment.json and returns
a phase result plus a `summary` the playbooks rely on (original security groups,
access keys, assumed roles...).

Idempotent: if pre_containment.json already exists (a retry, or a re-run after a
failure), the original is kept and its summary reused. Re-collecting after a partial
containment would record the quarantine state as the "original".

Env:
  FORENSICS_ROLE_ARN, EVIDENCE_BUCKET, EVIDENCE_KMS_KEY_ARN
  LOOKBACK_MINUTES (default 60)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from argus_shared import aws_utils as au
from argus_shared.constants import INCIDENT_TAG_KEY, MANAGED_TAG_KEY, MANAGED_TAG_VALUE
from argus_shared.phase import PhaseRecorder

log = logging.getLogger()
log.setLevel(logging.INFO)

MAX_OBJECT_VERSIONS = 2000


def lambda_handler(event, _context):
    envelope = event["envelope"]
    key = envelope["incident_key"]
    bucket = os.environ["EVIDENCE_BUCKET"]
    rec = PhaseRecorder("preserve_evidence")
    evidence_object = au.evidence_key(key, "pre_containment.json")

    existing = au.get_json(bucket, evidence_object)
    if existing is not None:
        rec.record("evidence:reuse", evidence_object, "ok", "pre_containment.json already exists")
        rec.extra.update({"evidence_uri": f"s3://{bucket}/{evidence_object}",
                          "summary": existing.get("summary", {})})
        return rec.result()

    session = au.assume_role(os.environ["FORENSICS_ROLE_ARN"], key)
    collectors = {"iam_user": collect_iam, "ec2_instance": collect_ec2, "s3_bucket": collect_s3}
    snapshot, summary = collectors[envelope["target"]["kind"]](session, envelope, rec)

    document = {
        "incident_id": envelope["incident_id"],
        "incident_key": key,
        "collected_at": au.now_iso(),
        "target": envelope["target"],
        "snapshot": snapshot,
        "summary": summary,
    }
    uri = au.put_json(bucket, evidence_object, document)
    rec.record("s3:PutObject", uri)
    rec.extra.update({"evidence_uri": uri, "summary": summary})
    return rec.result()


# ---------------------------------------------------------------- IAM

def collect_iam(session, envelope, rec):
    iam = au.client("iam", session)
    name = envelope["target"]["name"]

    user = iam.get_user(UserName=name)["User"]
    rec.record("iam:GetUser", name)
    groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=name)["Groups"]]
    try:
        login_profile = iam.get_login_profile(UserName=name)["LoginProfile"]
    except ClientError as exc:
        if au.error_code(exc) != "NoSuchEntity":
            raise
        login_profile = None
    attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
    inline = {}
    for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
        inline[policy_name] = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
    rec.record("iam:ListPolicies", name, detail={"attached": len(attached), "inline": len(inline)})

    keys = []
    for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
        keys.append({"access_key_id": k["AccessKeyId"], "status": k["Status"],
                     "created": str(k.get("CreateDate")), "last_used": {kk: str(v) for kk, v in last.items()}})
    rec.record("iam:ListAccessKeys", name, detail={"count": len(keys)})

    events = _lookup(session, "Username", name, envelope, rec)
    assumed_roles = sorted({
        e["request_parameters"]["roleArn"]
        for e in events
        if e["event_name"] == "AssumeRole" and not e["error_code"]
        and isinstance(e.get("request_parameters"), dict) and e["request_parameters"].get("roleArn")
    })

    snapshot = {
        "user": {k: str(v) for k, v in user.items()},
        "groups": groups,
        "login_profile": {k: str(v) for k, v in login_profile.items()} if login_profile else None,
        "attached_policies": attached,
        "inline_policies": inline,
        "access_keys": keys,
        "cloudtrail_management_events": events,
    }
    summary = {
        "access_key_ids": [k["access_key_id"] for k in keys],
        "has_login_profile": login_profile is not None,
        "assumed_roles": assumed_roles,
    }
    return snapshot, summary


# ---------------------------------------------------------------- EC2

def collect_ec2(session, envelope, rec):
    ec2 = au.client("ec2", session)
    iam = au.client("iam", session)
    instance_id = envelope["target"]["id"]
    key = envelope["incident_key"]

    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instance = reservations[0]["Instances"][0]
    rec.record("ec2:DescribeInstances", instance_id)

    enis = [
        {
            "eni_id": ni["NetworkInterfaceId"],
            "primary": ni.get("Attachment", {}).get("DeviceIndex") == 0,
            "groups": [g["GroupId"] for g in ni.get("Groups", [])],
            "private_ip": ni.get("PrivateIpAddress"),
            "public_ip": (ni.get("Association") or {}).get("PublicIp"),
        }
        for ni in instance.get("NetworkInterfaces", [])
    ]

    association = None
    instance_role = None
    assocs = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]},
                 {"Name": "state", "Values": ["associated"]}]
    )["IamInstanceProfileAssociations"]
    if assocs:
        a = assocs[0]
        association = {"association_id": a["AssociationId"], "profile_arn": a["IamInstanceProfile"]["Arn"]}
        profile_name = a["IamInstanceProfile"]["Arn"].split("/")[-1]
        roles = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"]
        if roles:
            instance_role = roles[0]["Arn"]
    rec.record("ec2:DescribeIamInstanceProfileAssociations", instance_id, detail=association)

    snapshots = []
    for mapping in instance.get("BlockDeviceMappings", []):
        volume_id = (mapping.get("Ebs") or {}).get("VolumeId")
        if not volume_id:
            continue
        snapshots.append(_snapshot_once(ec2, volume_id, key, instance_id, rec))

    snapshot = {
        "instance": json.loads(json.dumps(instance, default=str)),
        "network_interfaces": enis,
        "instance_profile_association": association,
        "instance_role_arn": instance_role,
        "ebs_snapshots": snapshots,
        "note": "Volatile memory is not captured (documented limitation).",
    }
    summary = {
        "enis": enis,
        "instance_profile_association": association,
        "instance_role_arn": instance_role,
        "snapshot_ids": [s["snapshot_id"] for s in snapshots],
    }
    return snapshot, summary


def _snapshot_once(ec2, volume_id, incident_key, instance_id, rec):
    """CreateSnapshot isn't idempotent: reuse a snapshot already tagged for this incident."""
    existing = ec2.describe_snapshots(
        OwnerIds=["self"],
        Filters=[{"Name": "volume-id", "Values": [volume_id]},
                 {"Name": f"tag:{INCIDENT_TAG_KEY}", "Values": [incident_key]}],
    )["Snapshots"]
    if existing:
        rec.record("ec2:CreateSnapshot", volume_id, "skipped", {"reused": existing[0]["SnapshotId"]})
        return {"volume_id": volume_id, "snapshot_id": existing[0]["SnapshotId"]}
    snap = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"Argus forensic snapshot of {instance_id} ({incident_key})",
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": INCIDENT_TAG_KEY, "Value": incident_key},
                     {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                     {"Key": "Name", "Value": f"argus-forensics-{incident_key}"}],
        }],
    )
    rec.record("ec2:CreateSnapshot", volume_id, detail={"snapshot_id": snap["SnapshotId"]})
    return {"volume_id": volume_id, "snapshot_id": snap["SnapshotId"]}


# ---------------------------------------------------------------- S3

def collect_s3(session, envelope, rec):
    s3 = au.client("s3", session)
    bucket = envelope["target"]["name"]

    def optional(fn, missing_codes, **kwargs):
        try:
            return fn(Bucket=bucket, **kwargs)
        except ClientError as exc:
            if au.error_code(exc) in missing_codes:
                return None
            raise

    policy = optional(s3.get_bucket_policy, {"NoSuchBucketPolicy"})
    policy_status = optional(s3.get_bucket_policy_status, {"NoSuchBucketPolicy"})
    acl = s3.get_bucket_acl(Bucket=bucket)
    pab = optional(s3.get_public_access_block, {"NoSuchPublicAccessBlockConfiguration"})
    ownership = optional(s3.get_bucket_ownership_controls, {"OwnershipControlsNotFoundError"})
    versioning = s3.get_bucket_versioning(Bucket=bucket)
    rec.record("s3:GetBucketConfiguration", bucket)

    versions, truncated = [], False
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            versions.append({"key": v["Key"], "version_id": v.get("VersionId"), "size": v.get("Size"),
                             "last_modified": str(v.get("LastModified")), "is_latest": v.get("IsLatest")})
        for d in page.get("DeleteMarkers", []):
            versions.append({"key": d["Key"], "version_id": d.get("VersionId"), "delete_marker": True,
                             "last_modified": str(d.get("LastModified")), "is_latest": d.get("IsLatest")})
        if len(versions) >= MAX_OBJECT_VERSIONS:
            truncated = True
            break
    rec.record("s3:ListObjectVersions", bucket, detail={"count": len(versions), "truncated": truncated})

    ownership_rule = None
    if ownership:
        rules = ownership["OwnershipControls"]["Rules"]
        ownership_rule = rules[0]["ObjectOwnership"] if rules else None

    snapshot = {
        "bucket_policy": json.loads(policy["Policy"]) if policy else None,
        "policy_status": (policy_status or {}).get("PolicyStatus"),
        "acl": {"owner": acl.get("Owner"), "grants": acl.get("Grants")},
        "public_access_block": (pab or {}).get("PublicAccessBlockConfiguration"),
        "object_ownership": ownership_rule,
        "versioning": versioning.get("Status", "Disabled"),
        "object_versions": versions,
        "object_versions_truncated": truncated,
        "note": "S3 data events (who read what) are collected later by CollectLateEvidence via Athena.",
    }
    summary = {
        "had_policy": policy is not None,
        "acls_enabled": ownership_rule != "BucketOwnerEnforced",
        "versioning": snapshot["versioning"],
    }
    return snapshot, summary


# ---------------------------------------------------------------- helpers

def _lookup(session, attr_key, attr_value, envelope, rec):
    minutes = int(os.environ.get("LOOKBACK_MINUTES", "60"))
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    events = au.lookup_management_events(attr_key, attr_value, start, end, session=session)
    rec.record("cloudtrail:LookupEvents", attr_value,
               detail={"count": len(events), "window_minutes": minutes,
                       "note": "management events only; recent calls may not be delivered yet"})
    return events
