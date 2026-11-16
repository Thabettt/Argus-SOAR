"""Static checks on the ASL template (rendered the same way Terraform's templatefile does)."""

import json
import re

import pytest
from conftest import ROOT, load_event, load_handler

TEMPLATE = ROOT / "terraform" / "modules" / "step_functions" / "playbook.asl.json.tftpl"

LAMBDA_RETRY = json.dumps({
    "ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException",
                    "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
    "IntervalSeconds": 2, "BackoffRate": 2, "MaxAttempts": 3})
CATCH = json.dumps({"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "MarkFailed"})

VARS = {
    "playbook": "iam",
    "validator_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-validator",
    "forensics_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-forensics",
    "playbook_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-iam-playbook",
    "package_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-package-evidence",
    "finalize_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-finalize",
    "notifier_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-notifier",
    "late_evidence_arn": "arn:aws:lambda:us-east-1:123456789012:function:argus-late-evidence",
    "table_name": "argus-incidents",
    "late_evidence_wait_seconds": "900",
    "lambda_retry": LAMBDA_RETRY,
    "catch_to_failed": CATCH,
}


@pytest.fixture(scope="module")
def definition():
    text = TEMPLATE.read_text()
    rendered = re.sub(r"\$\{(\w+)\}", lambda m: VARS[m.group(1)], text)
    return json.loads(rendered)


def test_template_has_no_unknown_variables():
    names = set(re.findall(r"\$\{(\w+)\}", TEMPLATE.read_text()))
    assert names <= set(VARS), names - set(VARS)


def test_every_transition_target_exists(definition):
    states = definition["States"]
    assert definition["StartAt"] in states
    for name, state in states.items():
        targets = [state.get("Next")] + [c["Next"] for c in state.get("Catch", [])]
        for target in filter(None, targets):
            assert target in states, f"{name} -> {target}"


def test_all_states_reachable(definition):
    states = definition["States"]
    seen, todo = set(), [definition["StartAt"]]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        state = states[name]
        todo += [t for t in [state.get("Next")] + [c["Next"] for c in state.get("Catch", [])] if t]
    assert seen == set(states)


def test_phases_after_record_incident_are_caught_to_mark_failed(definition):
    for name in ("PreserveEvidence", "Contain", "Eradicate", "PackageEvidence", "Finalize", "Notify"):
        state = definition["States"][name]
        assert state["Catch"][0]["Next"] == "MarkFailed", name
        assert state["Catch"][0]["ResultPath"] == "$.error", name  # keep the envelope for MarkFailed
        assert "TimeoutSeconds" in state, name  # task timeouts are catchable; execution timeouts are not


def test_phases_add_results_instead_of_replacing_state(definition):
    expected = {"PreserveEvidence": "$.evidence", "Contain": "$.containment", "Eradicate": "$.eradication",
                "PackageEvidence": "$.package", "Finalize": "$.finalize", "Notify": "$.notify"}
    for name, path in expected.items():
        assert definition["States"][name]["ResultPath"] == path


def test_idempotency_guard(definition):
    record = definition["States"]["RecordIncident"]
    assert "attribute_not_exists(finding_id)" in record["Parameters"]["ConditionExpression"]
    assert record["Catch"][0]["ErrorEquals"] == ["DynamoDB.ConditionalCheckFailedException"]
    assert record["Catch"][0]["Next"] == "AlreadyHandled"


def test_validator_accepts_state_machine_payload():
    """The state machine passes {"playbook", "finding"}; the validator returns the envelope."""
    import os

    os.environ["SIM_INSTANCE_IDS"] = "i-0123456789abcdef0"
    envelope = load_handler("validator").lambda_handler(
        {"playbook": "ec2", "finding": load_event("ec2_transformer_input.json")}, None)
    assert envelope["target"]["id"] == "i-0123456789abcdef0"


def test_resource_lock_follows_finding_guard(definition):
    states = definition["States"]
    assert states["RecordIncident"]["Next"] == "LockResource"
    lock = states["LockResource"]
    assert lock["Next"] == "PreserveEvidence"
    assert lock["Parameters"]["Item"]["finding_id"] == {"S.$": "$.envelope.resource_lock.key"}
    assert "lock_until < :now" in lock["Parameters"]["ConditionExpression"]
    assert lock["Catch"][0]["ErrorEquals"] == ["DynamoDB.ConditionalCheckFailedException"]
    assert lock["Catch"][0]["Next"] == "MarkDuplicate"
    assert states["MarkDuplicate"]["Next"] == "DuplicateForResource"


def test_failure_path_releases_only_its_own_lock(definition):
    states = definition["States"]
    assert states["MarkFailed"]["Next"] == "ReleaseLock"
    release = states["ReleaseLock"]
    assert release["Parameters"]["ConditionExpression"] == "owner_finding_id = :me"
    assert release["Next"] == release["Catch"][0]["Next"] == "NotifyFailure"


def test_validator_adds_resource_lock():
    import os
    from datetime import datetime, timezone

    os.environ["SIM_INSTANCE_IDS"] = "i-0123456789abcdef0"
    envelope = load_handler("validator").lambda_handler(
        {"playbook": "ec2", "finding": load_event("ec2_transformer_input.json")}, None)
    lock = envelope["resource_lock"]
    assert lock["key"] == "lock#arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0"
    # Comparable as a string with $$.State.EnteredTime (e.g. 2026-11-16T20:47:25.818Z)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    assert lock["until"] > now
