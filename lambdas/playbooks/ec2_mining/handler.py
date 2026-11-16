"""Playbook 2 - EC2 crypto-mining. Runs as the app-side remediation role.

contain:
  1. for EACH network interface: swap to the allow-all "untrack" group, then to the
     empty "isolate" group. Changing security groups does not cut connections that
     are already tracked; the allow-all group makes them untracked first, so the
     isolate group then drops them.
  2. disassociate the instance profile and add an aws:TokenIssueTime deny to the
     instance role (credentials stolen from IMDS keep working from anywhere otherwise)
  3. enable termination protection, tag QUARANTINED
eradicate:
  stop the instance (memory is lost - documented trade-off; disks were snapshotted)

Env: REMEDIATION_ROLE_ARN, UNTRACK_SG_ID, ISOLATE_SG_ID
"""

from __future__ import annotations

import logging
import os

from botocore.exceptions import ClientError

from argus_shared import aws_utils as au
from argus_shared.constants import (
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
    phase = event["phase"]
    if phase == "contain":
        return contain(au.client("ec2", session), au.client("iam", session), envelope,
                       event.get("evidence", {}))
    if phase == "eradicate":
        return eradicate(au.client("ec2", session), envelope)
    raise ValueError(f"unknown phase {phase!r}")


def contain(ec2, iam, envelope, evidence):
    rec = PhaseRecorder("contain")
    instance_id = envelope["target"]["id"]
    summary = evidence.get("summary") or {}
    untrack_sg = os.environ["UNTRACK_SG_ID"]
    isolate_sg = os.environ["ISOLATE_SG_ID"]

    enis = summary.get("enis") or _current_enis(ec2, instance_id)
    for eni in enis:
        eni_id = eni["eni_id"]
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=[untrack_sg])
        rec.record("ec2:ModifyNetworkInterfaceAttribute", eni_id, detail={"groups": [untrack_sg], "step": "untrack"})
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=[isolate_sg])
        rec.record("ec2:ModifyNetworkInterfaceAttribute", eni_id, detail={"groups": [isolate_sg], "step": "isolate"})

    association = summary.get("instance_profile_association")
    if association:
        try:
            ec2.disassociate_iam_instance_profile(AssociationId=association["association_id"])
            rec.record("ec2:DisassociateIamInstanceProfile", association["association_id"])
        except ClientError as exc:
            if au.error_code(exc) != "InvalidAssociationID.NotFound":
                raise
            rec.record("ec2:DisassociateIamInstanceProfile", association["association_id"],
                       "skipped", "already disassociated")

    role_arn = summary.get("instance_role_arn")
    if role_arn:
        role_name = role_arn.split("/")[-1]
        tags = iam.list_role_tags(RoleName=role_name)["Tags"]
        if au.has_managed_tag(tags):
            revoke_before = au.now_iso()
            iam.put_role_policy(RoleName=role_name, PolicyName=REVOKE_SESSIONS_POLICY_NAME,
                                PolicyDocument=au.revoke_older_sessions_policy(revoke_before))
            rec.record("iam:PutRolePolicy", role_arn, detail={"revoked_sessions_issued_before": revoke_before})
        else:
            rec.record("iam:PutRolePolicy", role_arn, "skipped", "role is not argus-managed; manual action needed")

    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
    rec.record("ec2:ModifyInstanceAttribute", instance_id, detail="DisableApiTermination=true")

    ec2.create_tags(Resources=[instance_id], Tags=[
        {"Key": STATUS_TAG_KEY, "Value": QUARANTINED},
        {"Key": INCIDENT_TAG_KEY, "Value": envelope["incident_key"]},
        {"Key": QUARANTINE_TIME_TAG_KEY, "Value": au.now_iso()},
    ])
    rec.record("ec2:CreateTags", instance_id, detail=QUARANTINED)
    return rec.result()


def eradicate(ec2, envelope):
    rec = PhaseRecorder("eradicate")
    instance_id = envelope["target"]["id"]
    resp = ec2.stop_instances(InstanceIds=[instance_id])
    state = resp["StoppingInstances"][0]["CurrentState"]["Name"]
    rec.record("ec2:StopInstances", instance_id, detail={"state": state})
    return rec.result()


def _current_enis(ec2, instance_id):
    """Fallback if forensics returned no ENI list."""
    instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    return [{"eni_id": ni["NetworkInterfaceId"]} for ni in instance.get("NetworkInterfaces", [])]
