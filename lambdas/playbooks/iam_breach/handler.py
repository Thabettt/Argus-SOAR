"""Playbook 1 - IAM breach. Runs as the app-side remediation role.

contain:
  1. deactivate every access key (no new sessions can be created)
  2. attach AWSDenyAll (explicit deny also covers GetSessionToken/GetFederationToken
     credentials, which are evaluated against the user's policies)
  3. for each role the user assumed (from forensics) that is Argus-managed, add an
     aws:TokenIssueTime deny: role sessions are NOT affected by the user's policies
eradicate:
  1. delete the console login profile
  2. tag the user QUARANTINED
  Access keys are deactivated, never deleted: they are evidence.

Every step is safe to repeat (Step Functions retries re-run the whole phase).

Env: REMEDIATION_ROLE_ARN
"""

from __future__ import annotations

import logging
import os

from botocore.exceptions import ClientError

from argus_shared import aws_utils as au
from argus_shared.constants import (
    DENY_ALL_POLICY_ARN,
    INCIDENT_TAG_KEY,
    QUARANTINE_TIME_TAG_KEY,
    QUARANTINED,
    REVOKE_SESSIONS_POLICY_NAME,
    STATUS_TAG_KEY,
)
from argus_shared.phase import PhaseRecorder

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, _context):
    envelope = event["envelope"]
    session = au.assume_role(os.environ["REMEDIATION_ROLE_ARN"], envelope["incident_key"])
    iam = au.client("iam", session)
    phase = event["phase"]
    if phase == "contain":
        return contain(iam, envelope, event.get("evidence", {}))
    if phase == "eradicate":
        return eradicate(iam, envelope)
    raise ValueError(f"unknown phase {phase!r}")


def contain(iam, envelope, evidence):
    rec = PhaseRecorder("contain")
    user = envelope["target"]["name"]

    for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        if key["Status"] == "Inactive":
            rec.record("iam:UpdateAccessKey", key["AccessKeyId"], "skipped", "already inactive")
            continue
        iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
        rec.record("iam:UpdateAccessKey", key["AccessKeyId"], detail="Inactive")

    iam.attach_user_policy(UserName=user, PolicyArn=DENY_ALL_POLICY_ARN)
    rec.record("iam:AttachUserPolicy", user, detail=DENY_ALL_POLICY_ARN)

    revoke_before = au.now_iso()
    for role_arn in (evidence.get("summary") or {}).get("assumed_roles", []):
        revoke_role_sessions(iam, role_arn, revoke_before, rec)

    return rec.result()


def revoke_role_sessions(iam, role_arn, revoke_before, rec):
    role_name = role_arn.split("/")[-1]
    try:
        tags = iam.list_role_tags(RoleName=role_name)["Tags"]
    except ClientError as exc:
        rec.record("iam:ListRoleTags", role_arn, "error", au.error_code(exc))
        return
    if not au.has_managed_tag(tags):
        # Never modify roles outside the simulation; a human must handle these.
        rec.record("iam:PutRolePolicy", role_arn, "skipped", "role is not argus-managed; manual action needed")
        return
    iam.put_role_policy(RoleName=role_name, PolicyName=REVOKE_SESSIONS_POLICY_NAME,
                        PolicyDocument=au.revoke_older_sessions_policy(revoke_before))
    rec.record("iam:PutRolePolicy", role_arn, detail={"revoked_sessions_issued_before": revoke_before})


def eradicate(iam, envelope):
    rec = PhaseRecorder("eradicate")
    user = envelope["target"]["name"]

    try:
        iam.delete_login_profile(UserName=user)
        rec.record("iam:DeleteLoginProfile", user)
    except ClientError as exc:
        if au.error_code(exc) != "NoSuchEntity":
            raise
        rec.record("iam:DeleteLoginProfile", user, "skipped", "no console password")

    iam.tag_user(UserName=user, Tags=[
        {"Key": STATUS_TAG_KEY, "Value": QUARANTINED},
        {"Key": INCIDENT_TAG_KEY, "Value": envelope["incident_key"]},
        {"Key": QUARANTINE_TIME_TAG_KEY, "Value": au.now_iso()},
    ])
    rec.record("iam:TagUser", user, detail=QUARANTINED)
    return rec.result()
