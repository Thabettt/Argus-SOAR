import json
import os

import boto3
import pytest
from conftest import ACCOUNT, load_event, load_handler

from argus_shared.envelope import build_envelope

BUCKET = "argus-sim-data-test"
PUBLIC_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Sid": "Public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
    "Resource": f"arn:aws:s3:::{BUCKET}/*"}]})


@pytest.fixture
def env(remediation_role):
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_tagging(Bucket=BUCKET, Tagging={"TagSet": [{"Key": "argus:managed", "Value": "true"}]})
    s3.put_object(Bucket=BUCKET, Key="customers.csv", Body=b"id,name\n1,Fake Person\n")
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    s3.put_bucket_policy(Bucket=BUCKET, Policy=PUBLIC_POLICY)
    os.environ["QUARANTINE_EXEMPT_PRINCIPAL_ARNS"] = (
        f"{remediation_role},arn:aws:iam::{ACCOUNT}:role/argus-auditor-role,arn:aws:iam::{ACCOUNT}:role/terraform")
    os.environ.pop("IAM_STATE_MACHINE_ARN", None)
    return s3, build_envelope(load_event("s3_transformer_input.json"), "s3")


def _evidence(envelope):
    os.environ["EVIDENCE_BUCKET"] = "argus-evidence-test"
    boto3.client("s3").create_bucket(Bucket="argus-evidence-test")
    return load_handler("forensics").lambda_handler({"envelope": envelope}, None)


def test_forensics_saves_public_policy_before_containment(env):
    s3, envelope = env
    evidence = _evidence(envelope)
    stored = json.loads(s3.get_object(Bucket="argus-evidence-test",
                                      Key=f"evidence/{envelope['incident_key']}/pre_containment.json")["Body"].read())
    assert stored["snapshot"]["bucket_policy"]["Statement"][0]["Sid"] == "Public"
    assert stored["snapshot"]["object_versions"][0]["key"] == "customers.csv"
    assert evidence["summary"]["had_policy"] is True


def test_forensics_reuses_existing_evidence(env):
    _s3, envelope = env
    first = _evidence(envelope)
    second = load_handler("forensics").lambda_handler({"envelope": envelope}, None)
    assert second["actions"][0]["action"] == "evidence:reuse"
    assert second["summary"] == first["summary"]


def test_contain_blocks_public_access_and_removes_policy(env):
    s3, envelope = env
    evidence = _evidence(envelope)
    load_handler("playbooks/s3_exfil").lambda_handler(
        {"phase": "contain", "envelope": envelope, "evidence": evidence}, None)

    pab = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    assert all(pab.values())
    with pytest.raises(s3.exceptions.ClientError):
        s3.get_bucket_policy(Bucket=BUCKET)


def test_contain_skips_acl_when_acls_disabled(env):
    _s3, envelope = env
    result = load_handler("playbooks/s3_exfil").lambda_handler(
        {"phase": "contain", "envelope": envelope, "evidence": {"summary": {"acls_enabled": False}}}, None)
    acl_action = [a for a in result["actions"] if a["action"] == "s3:PutBucketAcl"][0]
    assert acl_action["result"] == "skipped"


def test_eradicate_applies_quarantine_and_keeps_tags(env):
    s3, envelope = env
    load_handler("playbooks/s3_exfil").lambda_handler({"phase": "eradicate", "envelope": envelope}, None)

    stmt = json.loads(s3.get_bucket_policy(Bucket=BUCKET)["Policy"])["Statement"][0]
    assert stmt["Effect"] == "Deny" and stmt["Principal"] == "*"
    assert set(stmt["Resource"]) == {f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"}
    assert any(a.endswith("role/terraform") for a in stmt["Condition"]["ArnNotLike"]["aws:PrincipalArn"])

    assert s3.get_bucket_versioning(Bucket=BUCKET)["Status"] == "Enabled"
    tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=BUCKET)["TagSet"]}
    assert tags["argus:managed"] == "true"  # existing tag kept
    assert tags["argus:status"] == "QUARANTINED"


def test_eradicate_refuses_empty_exemption_list(env):
    _s3, envelope = env
    os.environ["QUARANTINE_EXEMPT_PRINCIPAL_ARNS"] = " "
    with pytest.raises(ValueError):
        load_handler("playbooks/s3_exfil").lambda_handler({"phase": "eradicate", "envelope": envelope}, None)


def test_eradicate_chains_into_iam_playbook(env):
    _s3, envelope = env
    sfn = boto3.client("stepfunctions")
    sm = sfn.create_state_machine(
        name="argus-iam-playbook",
        definition=json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}}),
        roleArn=f"arn:aws:iam::{ACCOUNT}:role/sfn")["stateMachineArn"]
    os.environ["IAM_STATE_MACHINE_ARN"] = sm
    handler = load_handler("playbooks/s3_exfil")

    result = handler.lambda_handler({"phase": "eradicate", "envelope": envelope}, None)
    chain = [a for a in result["actions"] if a["action"] == "states:StartExecution"][0]
    assert chain["result"] == "ok"

    execution = sfn.list_executions(stateMachineArn=sm)["executions"][0]
    payload = json.loads(sfn.describe_execution(executionArn=execution["executionArn"])["input"])
    assert payload["chained_from"] == envelope["finding_id"]
    chained = build_envelope(payload, "iam")
    assert chained["target"]["name"] == "argus-sim-exfil"
    assert chained["incident_key"] != envelope["incident_key"]

    # Running eradicate again must not start a second chained execution. (StartExecution with
    # the same name and input is idempotent while running, and ExecutionAlreadyExists after.)
    handler.lambda_handler({"phase": "eradicate", "envelope": envelope}, None)
    assert len(sfn.list_executions(stateMachineArn=sm)["executions"]) == 1
