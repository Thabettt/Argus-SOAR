"""Notifier: Discord webhook, SNS escalation, and the incident runbook.

Modes:
  success   - incident contained; webhook + runbook; SNS if severity >= threshold
  failure   - remediation failed; red webhook message; ALWAYS escalated to SNS
  warning   - late evidence collection failed (incident itself is fine)

The webhook URL lives in an SSM SecureString. A value of "disabled" (the Terraform
placeholder) skips the webhook.

Env: WEBHOOK_PARAM, SNS_TOPIC_ARN, ESCALATION_MIN_SEVERITY, EVIDENCE_BUCKET, EVIDENCE_KMS_KEY_ARN
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request

from argus_shared import aws_utils as au
from argus_shared.constants import SEVERITY_RANK

log = logging.getLogger()
log.setLevel(logging.INFO)

RED, ORANGE, GREEN = 0xE74C3C, 0xE67E22, 0x2ECC71


def lambda_handler(event, _context):
    mode = event.get("mode", "success")
    state = event["state"]
    envelope = state["envelope"]

    if mode == "success":
        message = success_message(state)
        color = ORANGE if envelope["severity"] in ("HIGH", "CRITICAL") else GREEN
        escalate = should_escalate(envelope["severity"], os.environ.get("ESCALATION_MIN_SEVERITY", "CRITICAL"))
    elif mode == "failure":
        message = failure_message(state)
        color, escalate = RED, True
    else:
        message = warning_message(state)
        color, escalate = ORANGE, False

    sent_webhook = post_webhook(message, color)
    if escalate and os.environ.get("SNS_TOPIC_ARN"):
        au.client("sns").publish(TopicArn=os.environ["SNS_TOPIC_ARN"],
                                 Subject=message["title"][:100],
                                 Message=plain_text(message))

    runbook_uri = write_runbook(state) if mode == "success" else None
    return {"mode": mode, "webhook_sent": sent_webhook, "escalated": escalate, "runbook_uri": runbook_uri}


def should_escalate(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(threshold.upper(), 4)


# ---------------------------------------------------------------- messages

def _action_lines(state, limit=12):
    lines = []
    for phase_name in ("containment", "eradication"):
        for a in (state.get(phase_name) or {}).get("actions", []):
            if a.get("result") == "ok":
                lines.append(f"{a['action']} -> {a['target']}")
    if len(lines) > limit:
        lines = lines[:limit] + [f"... and {len(lines) - limit} more"]
    return "\n".join(lines) or "none"


def success_message(state):
    env, pkg = state["envelope"], state.get("package") or {}
    ttc = pkg.get("time_to_contain_seconds")
    return {
        "title": f"Argus Incident Response - {env['severity']}",
        "fields": [
            ("Incident", env["incident_key"], True),
            ("Finding Type", env["finding_type"], True),
            ("Affected Resource", env["target"]["arn"], False),
            ("Actions Taken", _action_lines(state), False),
            ("Time to Containment", f"{ttc} seconds" if ttc is not None else "n/a", True),
            ("Detection Latency", f"{pkg.get('detection_latency_seconds')} seconds", True),
            ("Evidence Package", pkg.get("package_uri", "n/a"), False),
            ("SHA-256", pkg.get("sha256", "n/a"), False),
        ],
    }


def failure_message(state):
    env = state.get("envelope", {})
    err = state.get("error") or {}
    return {
        "title": "Argus remediation FAILED - manual action required",
        "fields": [
            ("Incident", env.get("incident_key", "unknown"), True),
            ("Finding Type", env.get("finding_type", "unknown"), True),
            ("Affected Resource", (env.get("target") or {}).get("arn", "unknown"), False),
            ("Error", str(err.get("Error", "unknown"))[:1000], False),
            ("Cause", str(err.get("Cause", ""))[:1000] or "n/a", False),
            ("Completed Actions", _action_lines(state), False),
        ],
    }


def warning_message(state):
    env = state.get("envelope", {})
    err = state.get("late_error") or {}
    return {
        "title": "Argus: late evidence collection failed (incident was contained)",
        "fields": [
            ("Incident", env.get("incident_key", "unknown"), True),
            ("Error", str(err.get("Error", "unknown"))[:1000], False),
        ],
    }


def plain_text(message):
    return message["title"] + "\n\n" + "\n".join(f"{n}: {v}" for n, v, _ in message["fields"])


def post_webhook(message, color) -> bool:
    param = os.environ.get("WEBHOOK_PARAM")
    if not param:
        return False
    url = au.get_ssm_parameter(param)
    if not url or url.strip().lower() == "disabled":
        log.info("webhook disabled")
        return False
    payload = {"embeds": [{
        "title": message["title"],
        "color": color,
        "fields": [{"name": n, "value": str(v)[:1024], "inline": inline} for n, v, inline in message["fields"]],
        "timestamp": au.now_iso(),
    }]}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "argus-soar"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - URL comes from our own SSM parameter
        log.info("webhook status %s", resp.status)
    return True


# ---------------------------------------------------------------- runbook

def write_runbook(state) -> str:
    env, pkg = state["envelope"], state.get("package") or {}
    timeline = [
        (env["finding_created"], "Finding created by GuardDuty"),
        (env["event_received"], "Received by EventBridge"),
        ((state.get("evidence") or {}).get("completed_at"), "Evidence preserved"),
        ((state.get("containment") or {}).get("completed_at"), "Containment executed"),
        ((state.get("eradication") or {}).get("completed_at"), "Eradication complete"),
    ]
    recovery = {
        "iam_user": "Review evidence. Delete the deactivated keys, detach AWSDenyAll only if the user is "
                    "still needed, remove ArgusRevokeOlderSessions from any roles once the root cause is fixed.",
        "ec2_instance": "Review evidence and snapshots. Rebuild from a clean AMI (IMDSv2 required, no open SSH), "
                        "restore original security groups and instance profile, remove the revoke-sessions policy.",
        "s3_bucket": "Review data events (supplemental.json) to scope what was read. Replace the quarantine "
                     "policy with the intended policy; keep Block Public Access on.",
    }[env["target"]["kind"]]

    lines = [
        f"# Incident Runbook - {env['incident_key']}",
        f"**Date:** {env['event_received'][:10]}  **Severity:** {env['severity']}  **Type:** {env['finding_type']}",
        f"**Target:** `{env['target']['arn']}`",
        "",
        "## Timeline",
        *[f"- {t or 'n/a'} - {label}" for t, label in timeline],
        "",
        "## Actions Taken",
        *[f"- `{line}`" for line in _action_lines(state, limit=100).splitlines()],
        "",
        "## Evidence Location",
        pkg.get("package_uri", "n/a"),
        "",
        "## SHA-256 Digest",
        f"`{pkg.get('sha256', 'n/a')}`",
        "",
        "## Recovery Steps",
        recovery,
        "",
    ]
    key = f"runbooks/{env['incident_key']}.md"
    return au.put_bytes(os.environ["EVIDENCE_BUCKET"], key, "\n".join(lines).encode(), "text/markdown")
