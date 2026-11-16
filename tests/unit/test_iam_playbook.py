import json

import boto3
import pytest
from conftest import load_event, load_handler

from argus_shared.constants import DENY_ALL_POLICY_ARN, REVOKE_SESSIONS_POLICY_NAME
from argus_shared.envelope import build_envelope

MANAGED = [{"Key": "argus:managed", "Value": "true"}]
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


@pytest.fixture
def setup(remediation_role):
    iam = boto3.client("iam")
    iam.create_user(UserName="argus-sim-backdoor", Tags=MANAGED)
    keys = [iam.create_access_key(UserName="argus-sim-backdoor")["AccessKey"]["AccessKeyId"] for _ in range(2)]
    managed_role = iam.create_role(RoleName="argus-sim-app-role", AssumeRolePolicyDocument=TRUST, Tags=MANAGED)
    other_role = iam.create_role(RoleName="prod-role", AssumeRolePolicyDocument=TRUST)
    envelope = build_envelope(load_event("iam_transformer_input.json"), "iam")
    evidence = {"summary": {"assumed_roles": [managed_role["Role"]["Arn"], other_role["Role"]["Arn"]]}}
    return iam, keys, envelope, evidence


def test_contain_deactivates_keys_denies_and_revokes(setup):
    iam, keys, envelope, evidence = setup
    handler = load_handler("playbooks/iam_breach")

    result = handler.lambda_handler({"phase": "contain", "envelope": envelope, "evidence": evidence}, None)

    statuses = {k["AccessKeyId"]: k["Status"]
                for k in iam.list_access_keys(UserName="argus-sim-backdoor")["AccessKeyMetadata"]}
    assert statuses == {k: "Inactive" for k in keys}
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="argus-sim-backdoor")["AttachedPolicies"]]
    assert attached == [DENY_ALL_POLICY_ARN]

    policy = iam.get_role_policy(RoleName="argus-sim-app-role", PolicyName=REVOKE_SESSIONS_POLICY_NAME)
    condition = policy["PolicyDocument"]["Statement"][0]["Condition"]
    assert "aws:TokenIssueTime" in condition["DateLessThan"]

    # The unmanaged role is never touched.
    assert iam.list_role_policies(RoleName="prod-role")["PolicyNames"] == []
    skipped = [a for a in result["actions"] if a["result"] == "skipped"]
    assert any("prod-role" in a["target"] for a in skipped)
    assert result["phase"] == "contain" and result["started_at"] <= result["completed_at"]


def test_contain_is_idempotent(setup):
    iam, _keys, envelope, evidence = setup
    handler = load_handler("playbooks/iam_breach")
    event = {"phase": "contain", "envelope": envelope, "evidence": evidence}
    handler.lambda_handler(event, None)
    second = handler.lambda_handler(event, None)
    assert [a["result"] for a in second["actions"] if a["action"] == "iam:UpdateAccessKey"] == ["skipped", "skipped"]


def test_eradicate_without_login_profile_and_tags_user(setup):
    iam, _keys, envelope, _evidence = setup
    handler = load_handler("playbooks/iam_breach")
    result = handler.lambda_handler({"phase": "eradicate", "envelope": envelope}, None)

    tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName="argus-sim-backdoor")["Tags"]}
    assert tags["argus:status"] == "QUARANTINED"
    assert tags["argus:incident_key"] == envelope["incident_key"]
    assert result["actions"][0]["result"] == "skipped"


def test_eradicate_deletes_login_profile(setup):
    iam, _keys, envelope, _evidence = setup
    iam.create_login_profile(UserName="argus-sim-backdoor", Password="Testing-Passw0rd!")
    handler = load_handler("playbooks/iam_breach")
    handler.lambda_handler({"phase": "eradicate", "envelope": envelope}, None)
    with pytest.raises(iam.exceptions.NoSuchEntityException):
        iam.get_login_profile(UserName="argus-sim-backdoor")
