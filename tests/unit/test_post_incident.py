"""PackageEvidence, Finalize and Notifier."""

import hashlib
import json
import os

import boto3
import pytest
from conftest import load_event, load_handler

from argus_shared.envelope import build_envelope

EVIDENCE = "argus-evidence-test"


@pytest.fixture
def state():
    os.environ["EVIDENCE_BUCKET"] = EVIDENCE
    boto3.client("s3").create_bucket(Bucket=EVIDENCE)
    envelope = build_envelope(load_event("iam_transformer_input.json"), "iam")
    return {
        "envelope": envelope,
        "evidence": {"phase": "preserve_evidence", "started_at": "2026-11-20T14:03:14Z",
                     "completed_at": "2026-11-20T14:03:20Z",
                     "actions": [{"action": "iam:GetUser", "target": "argus-sim-backdoor", "result": "ok",
                                  "at": "2026-11-20T14:03:15Z"}]},
        "containment": {"phase": "contain", "started_at": "2026-11-20T14:03:21Z",
                        "completed_at": "2026-11-20T14:03:42Z",
                        "actions": [{"action": "iam:AttachUserPolicy", "target": "argus-sim-backdoor",
                                     "result": "ok", "at": "2026-11-20T14:03:30Z"}]},
        "eradication": {"phase": "eradicate", "started_at": "2026-11-20T14:03:43Z",
                        "completed_at": "2026-11-20T14:03:45Z", "actions": []},
    }


def test_package_digest_matches_stored_bytes(state):
    s3 = boto3.client("s3")
    result = load_handler("package_evidence").lambda_handler({"state": state}, None)

    key = state["envelope"]["incident_key"]
    stored = s3.get_object(Bucket=EVIDENCE, Key=f"evidence/{key}/final_package.json")["Body"].read()
    assert hashlib.sha256(stored).hexdigest() == result["sha256"]
    digest_line = s3.get_object(Bucket=EVIDENCE, Key=f"evidence/{key}/sha256.txt")["Body"].read().decode()
    assert digest_line == f"{result['sha256']}  final_package.json\n"

    bundle = json.loads(stored)
    assert bundle["timestamps"]["time_to_contain_seconds"] == 30.0  # 14:03:12 -> 14:03:42
    assert bundle["timestamps"]["detection_latency_seconds"] == pytest.approx(271.877)
    assert [a["phase"] for a in bundle["remediation_actions"]] == ["preserve_evidence", "contain"]


def test_package_is_deterministic(state):
    handler = load_handler("package_evidence")
    first = handler.lambda_handler({"state": state}, None)
    second = handler.lambda_handler({"state": state}, None)
    assert first["sha256"] == second["sha256"]


def test_finalize_marks_complete_and_resolves(state, monkeypatch):
    ddb = boto3.client("dynamodb")
    ddb.create_table(TableName="argus-incidents", BillingMode="PAY_PER_REQUEST",
                     KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}])
    ddb.put_item(TableName="argus-incidents", Item={"finding_id": {"S": state["envelope"]["occurrence_id"]},
                                                   "status": {"S": "IN_PROGRESS"}})
    os.environ["INCIDENTS_TABLE"] = "argus-incidents"
    state["package"] = {"package_uri": "s3://x/y", "sha256": "abc", "time_to_contain_seconds": 30.0}

    handler = load_handler("finalize")
    calls = []

    class FakeSecurityHub:
        def batch_update_findings(self, **kwargs):
            calls.append(kwargs)
            return {"ProcessedFindings": kwargs["FindingIdentifiers"], "UnprocessedFindings": []}

    real_client = handler.au.client
    monkeypatch.setattr(handler.au, "client",
                        lambda svc, session=None: FakeSecurityHub() if svc == "securityhub" else real_client(svc))

    result = handler.lambda_handler({"state": state}, None)
    item = ddb.get_item(TableName="argus-incidents", Key={"finding_id": {"S": state["envelope"]["occurrence_id"]}})["Item"]
    assert item["status"]["S"] == "COMPLETE"
    assert result["securityhub_resolved"] is True
    assert calls[0]["Workflow"] == {"Status": "RESOLVED"}
    assert calls[0]["FindingIdentifiers"][0]["ProductArn"] == state["envelope"]["product_arn"]

    # Chained incidents have a synthetic finding ID: no Security Hub call.
    calls.clear()
    state["envelope"]["chained_from"] = "parent"
    assert handler.lambda_handler({"state": state}, None)["securityhub_resolved"] is False
    assert calls == []


@pytest.mark.parametrize("severity,threshold,expected", [
    ("HIGH", "CRITICAL", False), ("CRITICAL", "CRITICAL", True),
    ("HIGH", "HIGH", True), ("MEDIUM", "HIGH", False), ("LOW", "LOW", True),
])
def test_escalation_threshold(severity, threshold, expected):
    assert load_handler("notifier").should_escalate(severity, threshold) is expected


def test_notifier_success_with_webhook_disabled_writes_runbook(state):
    boto3.client("ssm").put_parameter(Name="/argus/webhook", Value="disabled", Type="SecureString")
    topic = boto3.client("sns").create_topic(Name="argus-escalation")["TopicArn"]
    os.environ.update({"WEBHOOK_PARAM": "/argus/webhook", "SNS_TOPIC_ARN": topic,
                       "ESCALATION_MIN_SEVERITY": "MEDIUM"})
    state["package"] = {"package_uri": "s3://x/y", "sha256": "abc", "time_to_contain_seconds": 30.0,
                        "detection_latency_seconds": 271.9}

    result = load_handler("notifier").lambda_handler({"mode": "success", "state": state}, None)
    assert result == {"mode": "success", "webhook_sent": False, "escalated": True,
                      "runbook_uri": f"s3://{EVIDENCE}/runbooks/{state['envelope']['incident_key']}.md"}
    runbook = boto3.client("s3").get_object(
        Bucket=EVIDENCE, Key=f"runbooks/{state['envelope']['incident_key']}.md")["Body"].read().decode()
    assert "## Recovery" in runbook and "Attached AWSDenyAll to argus-sim-backdoor" in runbook


def test_notifier_failure_always_escalates(state):
    boto3.client("ssm").put_parameter(Name="/argus/webhook", Value="disabled", Type="SecureString")
    topic = boto3.client("sns").create_topic(Name="argus-escalation")["TopicArn"]
    os.environ.update({"WEBHOOK_PARAM": "/argus/webhook", "SNS_TOPIC_ARN": topic,
                       "ESCALATION_MIN_SEVERITY": "CRITICAL"})
    state["error"] = {"Error": "AccessDenied", "Cause": "not authorized to perform iam:AttachUserPolicy"}
    result = load_handler("notifier").lambda_handler({"mode": "failure", "state": state}, None)
    assert result["escalated"] is True and result["runbook_uri"] is None


# The exact Cause from the first live run's failure email.
LIVE_CAUSE = json.dumps({
    "errorMessage": "An error occurred (SnapshotCreationPerVolumeRateExceeded) when calling the CreateSnapshot "
                    "operation: The maximum per volume CreateSnapshot request rate has been exceeded. Use an "
                    "increasing or variable sleep interval between requests.",
    "errorType": "ClientError",
    "stackTrace": ["  File \"/var/task/handler.py\", line 52, in lambda_handler\n"],
})


def test_guardduty_type_is_readable():
    gt = load_handler("notifier").guardduty_type
    assert gt("TTPs/Command and Control/CryptoCurrency:EC2-BitcoinTool.B!DNS") == "CryptoCurrency:EC2/BitcoinTool.B!DNS"
    assert gt("TTPs/Initial Access/UnauthorizedAccess:IAMUser-MaliciousIPCaller.Custom") == \
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"


def test_failure_email_is_readable(state):
    notifier = load_handler("notifier")
    del state["containment"], state["eradication"]
    state["error"] = {"Error": "ClientError", "Cause": LIVE_CAUSE}
    msg = notifier.failure_message(state, {"Execution": "https://example/exec"})
    assert "Failed step   Contain" in msg["text"]
    assert "SnapshotCreationPerVolumeRateExceeded (during CreateSnapshot)" in msg["text"]
    assert "The maximum per volume CreateSnapshot request rate" in msg["text"]
    assert "stackTrace" not in msg["text"] and "handler.py" not in msg["text"]
    assert msg["subject"].startswith("[Argus] FAILED: Compromised IAM credentials on argus-sim-backdoor")


def test_success_email_has_timeline_actions_and_links(state):
    notifier = load_handler("notifier")
    state["package"] = {"package_uri": "s3://b/evidence/k/final_package.json", "sha256": "ab" * 32,
                        "time_to_contain_seconds": 30.0, "detection_latency_seconds": 271.9}
    links = notifier.console_links(state["envelope"], state, "arn:aws:states:us-east-1:111122223333:execution:x:y")
    msg = notifier.success_message(state, links)
    assert msg["subject"] == "[Argus] MEDIUM contained: Compromised IAM credentials on argus-sim-backdoor"
    assert "30.0 s after receipt" in msg["text"] and "detection took 4 min 32 s" in msg["text"]
    assert "1. Attached AWSDenyAll to argus-sim-backdoor" in msg["text"]
    assert "states/home?region=us-east-1#/v2/executions/details/arn:aws:states" in msg["text"]
    assert "guardduty/home?region=us-east-1#/findings" in msg["text"]
