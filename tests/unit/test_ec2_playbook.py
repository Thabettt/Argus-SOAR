import json
import os

import boto3
import pytest
from conftest import load_event, load_handler

from argus_shared.envelope import build_envelope

MANAGED = [{"Key": "argus:managed", "Value": "true"}]


@pytest.fixture
def env(remediation_role):
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")
    vpc = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.42.1.0/24")["Subnet"]["SubnetId"]
    open_sg = ec2.create_security_group(GroupName="open", Description="open", VpcId=vpc)["GroupId"]
    untrack = ec2.create_security_group(GroupName="untrack", Description="u", VpcId=vpc)["GroupId"]
    isolate = ec2.create_security_group(GroupName="isolate", Description="i", VpcId=vpc)["GroupId"]
    os.environ.update({"UNTRACK_SG_ID": untrack, "ISOLATE_SG_ID": isolate})

    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    role = iam.create_role(RoleName="argus-sim-instance-role", AssumeRolePolicyDocument=trust, Tags=MANAGED)
    iam.create_instance_profile(InstanceProfileName="argus-sim-instance-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="argus-sim-instance-profile",
                                     RoleName="argus-sim-instance-role")

    instance = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SubnetId=subnet,
                                 SecurityGroupIds=[open_sg],
                                 IamInstanceProfile={"Name": "argus-sim-instance-profile"})["Instances"][0]
    instance_id = instance["InstanceId"]

    raw = load_event("ec2_transformer_input.json")
    raw["resources"][0]["Id"] = f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}"
    envelope = build_envelope(raw, "ec2")
    return ec2, iam, envelope, instance_id, open_sg, isolate, role["Role"]["Arn"]


def _forensics(ec2_env):
    ec2, _iam, envelope, *_ = ec2_env
    os.environ["EVIDENCE_BUCKET"] = "argus-evidence-test"
    boto3.client("s3").create_bucket(Bucket="argus-evidence-test")
    forensics = load_handler("forensics")
    return forensics.lambda_handler({"envelope": envelope}, None)


def test_forensics_records_original_groups_and_snapshots(env):
    _ec2, _iam, _envelope, instance_id, open_sg, *_ = env
    evidence = _forensics(env)
    summary = evidence["summary"]
    assert summary["enis"][0]["groups"] == [open_sg]
    assert summary["instance_role_arn"].endswith("role/argus-sim-instance-role")
    assert summary["instance_profile_association"]["association_id"]
    assert len(summary["snapshot_ids"]) >= 1


def test_forensics_snapshot_is_not_duplicated_on_retry(env):
    first = _forensics(env)
    # Simulate a retry that lost the stored object: snapshots must still be reused.
    boto3.client("s3").delete_object(Bucket="argus-evidence-test",
                                     Key=f"evidence/{env[2]['incident_key']}/pre_containment.json")
    second = _forensics(env)
    assert first["summary"]["snapshot_ids"] == second["summary"]["snapshot_ids"]


def test_contain_isolates_every_eni_and_revokes_credentials(env):
    ec2, iam, envelope, instance_id, _open_sg, isolate, _role_arn = env
    evidence = _forensics(env)
    handler = load_handler("playbooks/ec2_mining")

    result = handler.lambda_handler({"phase": "contain", "envelope": envelope, "evidence": evidence}, None)

    # Real AWS REPLACES the ENI's groups; moto appends them, so check the calls Argus made
    # (exact group list per call) and that the isolate group is attached.
    instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    for ni in instance["NetworkInterfaces"]:
        assert isolate in [g["GroupId"] for g in ni["Groups"]]

    swaps = [a["detail"] for a in result["actions"] if a["action"] == "ec2:ModifyNetworkInterfaceAttribute"]
    assert [s["step"] for s in swaps] == ["untrack", "isolate"]  # untrack must come first, or live sessions survive
    assert swaps[0]["groups"] == [os.environ["UNTRACK_SG_ID"]]
    assert swaps[-1]["groups"] == [isolate]

    assert ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}, {"Name": "state", "Values": ["associated"]}]
    )["IamInstanceProfileAssociations"] == []
    assert "ArgusRevokeOlderSessions" in iam.list_role_policies(RoleName="argus-sim-instance-role")["PolicyNames"]

    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert attr["DisableApiTermination"]["Value"] is True


def test_contain_twice_is_safe(env):
    _ec2, _iam, envelope, *_ = env
    evidence = _forensics(env)
    handler = load_handler("playbooks/ec2_mining")
    handler.lambda_handler({"phase": "contain", "envelope": envelope, "evidence": evidence}, None)
    again = handler.lambda_handler({"phase": "contain", "envelope": envelope, "evidence": evidence}, None)
    assert any(a["result"] == "skipped" for a in again["actions"]
               if a["action"] == "ec2:DisassociateIamInstanceProfile")


def test_eradicate_stops_instance(env):
    ec2, _iam, envelope, instance_id, *_ = env
    handler = load_handler("playbooks/ec2_mining")
    handler.lambda_handler({"phase": "eradicate", "envelope": envelope}, None)
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state in ("stopping", "stopped")


def test_snapshot_rate_limit_is_retried(env, monkeypatch):
    """Several findings for one instance once hit SnapshotCreationPerVolumeRateExceeded."""
    from botocore.exceptions import ClientError

    forensics = load_handler("forensics")
    monkeypatch.setattr(forensics, "SNAPSHOT_BACKOFF_SECONDS", 0)
    ec2 = env[0]
    calls = {"n": 0}
    real = ec2.create_snapshot

    class Flaky:
        def __getattr__(self, name):
            return getattr(ec2, name)

        def create_snapshot(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ClientError({"Error": {"Code": "SnapshotCreationPerVolumeRateExceeded", "Message": "slow down"}},
                                  "CreateSnapshot")
            return real(**kw)

    vol = ec2.describe_instances(InstanceIds=[env[3]])["Reservations"][0]["Instances"][0][
        "BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    from argus_shared.phase import PhaseRecorder
    result = forensics._snapshot_once(Flaky(), vol, "key123", env[3], PhaseRecorder("p"))
    assert result["snapshot_id"].startswith("snap-") and calls["n"] == 2
