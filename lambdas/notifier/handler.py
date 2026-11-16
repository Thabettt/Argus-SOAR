"""Notifier: incident emails (SNS), Discord webhook, and the incident runbook.

Modes:
  success   - incident contained; webhook + runbook; email if severity >= threshold
  failure   - remediation failed; ALWAYS emailed, with the parsed error and next steps
  warning   - late evidence collection failed (the incident itself was contained)

The webhook URL lives in an SSM SecureString. "disabled" (the Terraform placeholder)
skips the webhook.

Env: WEBHOOK_PARAM, SNS_TOPIC_ARN, ESCALATION_MIN_SEVERITY, EVIDENCE_BUCKET, EVIDENCE_KMS_KEY_ARN
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
import urllib.request

from argus_shared import aws_utils as au
from argus_shared.constants import SEVERITY_RANK

log = logging.getLogger()
log.setLevel(logging.INFO)

RED, ORANGE, GREEN = 0xE74C3C, 0xE67E22, 0x2ECC71

SCENARIO = {
    "iam": "Compromised IAM credentials",
    "ec2": "Crypto-mining on EC2",
    "s3": "S3 data exfiltration",
}

PHASES = [("evidence", "PreserveEvidence"), ("containment", "Contain"),
          ("eradication", "Eradicate"), ("package", "PackageEvidence"), ("finalize", "Finalize")]

RECOVERY = {
    "iam_user": "Review the evidence. Delete the deactivated keys; detach AWSDenyAll only if the user is "
                "still needed; remove ArgusRevokeOlderSessions from roles once the root cause is fixed.",
    "ec2_instance": "Review the evidence and snapshots. Rebuild from a clean AMI (IMDSv2, no open SSH), "
                    "restore the original security groups and instance profile, then remove the "
                    "revoke-sessions policy. In the lab: reset_simulation.py --ec2 --start-instance",
    "s3_bucket": "Review supplemental.json (S3 data events) to scope what was read. Replace the quarantine "
                 "policy with the intended policy and keep Block Public Access on.",
}


def lambda_handler(event, _context):
    mode = event.get("mode", "success")
    state = event["state"]
    envelope = state.get("envelope", {})
    links = console_links(envelope, state, event.get("execution_arn"))

    if mode == "success":
        msg = success_message(state, links)
        escalate = should_escalate(envelope["severity"], os.environ.get("ESCALATION_MIN_SEVERITY", "CRITICAL"))
    elif mode == "failure":
        msg = failure_message(state, links)
        escalate = True
    else:
        msg = warning_message(state, links)
        escalate = False

    sent_webhook = post_webhook(msg)
    if escalate and os.environ.get("SNS_TOPIC_ARN"):
        au.client("sns").publish(TopicArn=os.environ["SNS_TOPIC_ARN"], Subject=msg["subject"][:100],
                                 Message=msg["text"])

    runbook_uri = write_runbook(state) if mode == "success" else None
    return {"mode": mode, "webhook_sent": sent_webhook, "escalated": escalate, "runbook_uri": runbook_uri}


def should_escalate(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity.upper(), 0) >= SEVERITY_RANK.get(threshold.upper(), 4)


# ================================================================ formatting helpers

def guardduty_type(asff_type: str) -> str:
    """'TTPs/Command and Control/CryptoCurrency:EC2-BitcoinTool.B!DNS' -> 'CryptoCurrency:EC2/BitcoinTool.B!DNS'."""
    last = (asff_type or "").split("/")[-1]
    if ":" in last:
        purpose, rest = last.split(":", 1)
        return f"{purpose}:{rest.replace('-', '/', 1)}"
    return last or "unknown"


def duration(seconds) -> str:
    if seconds is None:
        return "n/a"
    seconds = float(seconds)
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes} min {secs} s"


def hhmmss(iso: str | None) -> str:
    if not iso:
        return "n/a"
    return au.parse_iso(iso).strftime("%H:%M:%S UTC")


def describe_action(a: dict) -> str:
    action, target, detail = a.get("action", ""), a.get("target", ""), a.get("detail")
    step = detail.get("step") if isinstance(detail, dict) else None
    text = {
        "iam:UpdateAccessKey": f"Deactivated access key {target}",
        "iam:AttachUserPolicy": f"Attached AWSDenyAll to {target} (explicit deny on everything)",
        "iam:PutRolePolicy": f"Revoked existing sessions of role {target.split('/')[-1]}",
        "iam:DeleteLoginProfile": f"Removed console password of {target}",
        "iam:TagUser": f"Tagged {target} QUARANTINED",
        "ec2:ModifyNetworkInterfaceAttribute": f"Isolated {target}: no new inbound or outbound connections",
        "ec2:ReplaceNetworkAclAssociation": f"Put subnet {target} behind the deny-all NACL (cuts live connections)",
        "ec2:DisassociateIamInstanceProfile": "Detached the instance profile (no new instance credentials)",
        "ec2:ModifyInstanceAttribute": f"Enabled termination protection on {target}",
        "ec2:CreateTags": f"Tagged {target} QUARANTINED",
        "ec2:StopInstances": f"Stopped {target} (disk kept for forensics)",
        "s3:PutBucketPublicAccessBlock": f"Re-enabled all four Block Public Access settings on {target}",
        "s3:DeleteBucketPolicy": f"Removed the bucket policy of {target}",
        "s3:PutBucketAcl": f"Reset the ACL of {target} to private",
        "s3:PutBucketPolicy": f"Applied the quarantine policy to {target} (deny all but responders)",
        "s3:PutBucketVersioning": f"Ensured versioning on {target}",
        "s3:PutBucketTagging": f"Tagged {target} QUARANTINED",
        "states:StartExecution": f"Started the IAM playbook for {target}",
    }.get(action, f"{action} on {target}")
    if a.get("result") == "skipped":
        reason = detail if isinstance(detail, str) else "already done"
        text += f" - skipped ({reason})"
    return text


def remediation_lines(state) -> list[str]:
    lines = []
    for phase in ("containment", "eradication"):
        for a in (state.get(phase) or {}).get("actions", []):
            if a.get("result") in ("ok", "skipped"):
                lines.append(describe_action(a))
    return lines


def console_links(envelope: dict, state: dict, execution_arn: str | None) -> dict:
    region = envelope.get("region") or os.environ.get("AWS_REGION", "us-east-1")
    links = {}
    if execution_arn:
        links["Execution"] = (f"https://{region}.console.aws.amazon.com/states/home?region={region}"
                              f"#/v2/executions/details/{execution_arn}")
    key, bucket = envelope.get("incident_key"), os.environ.get("EVIDENCE_BUCKET")
    if key and bucket:
        links["Evidence"] = (f"https://s3.console.aws.amazon.com/s3/buckets/{bucket}?region={region}"
                             f"&prefix={urllib.parse.quote(f'evidence/{key}/')}")
    finding_id = envelope.get("finding_id", "")
    if "/finding/" in finding_id:
        links["Finding"] = (f"https://{region}.console.aws.amazon.com/guardduty/home?region={region}"
                            f"#/findings?macros=current&fId={finding_id.split('/finding/')[-1]}")
    return links


def parse_error(err: dict) -> dict:
    """Turn a Step Functions error (with a Lambda stack trace as Cause) into readable parts."""
    name, cause = str(err.get("Error", "unknown")), err.get("Cause") or ""
    message = cause
    try:
        parsed = json.loads(cause)
        message = parsed.get("errorMessage", cause)
        name = parsed.get("errorType", name)
    except (json.JSONDecodeError, TypeError):
        pass
    m = re.match(r"An error occurred \((\w+)\) when calling the (\w+) operation: (.*)", str(message), re.S)
    if m:
        return {"code": m.group(1), "operation": m.group(2), "message": m.group(3).strip()[:400]}
    return {"code": name, "operation": None, "message": str(message).strip()[:400] or "no details"}


def failed_phase(state) -> str:
    for key, name in PHASES:
        if not state.get(key):
            return name
    return "Notify"


# ================================================================ messages
# Each message: subject (email), text (email body), title/color/fields (Discord embed).

def success_message(state, links):
    env, pkg = state["envelope"], state.get("package") or {}
    containment = state.get("containment") or {}
    target = env["target"]
    scenario = SCENARIO.get(env.get("playbook"), "Security incident")
    ttc, latency = pkg.get("time_to_contain_seconds"), pkg.get("detection_latency_seconds")
    actions = remediation_lines(state)
    snapshots = ((state.get("evidence") or {}).get("summary") or {}).get("snapshot_ids") or []

    lines = [
        "ARGUS INCIDENT RESPONSE: CONTAINED",
        "",
        f"{scenario} - severity {env['severity']}",
        f"Finding   {guardduty_type(env['finding_type'])}",
        f"Target    {target['name']}",
        f"          {target['arn']}",
        "",
        "TIMELINE",
        f"  Detected by GuardDuty   {hhmmss(env.get('finding_updated') or env.get('finding_created'))}",
        f"  Received by Argus       {hhmmss(env.get('event_received'))}   (detection took {duration(latency)})",
        f"  Contained               {hhmmss(containment.get('completed_at'))}   ({duration(ttc)} after receipt)",
        "",
        "WHAT ARGUS DID",
        *[f"  {i}. {line}" for i, line in enumerate(actions, 1)],
        "",
        "EVIDENCE (SHA-256 verified, under S3 Object Lock)",
        f"  Package     {pkg.get('package_uri', 'n/a')}",
        f"  SHA-256     {pkg.get('sha256', 'n/a')}",
    ]
    if snapshots:
        lines.append(f"  Snapshots   {', '.join(snapshots)}")
    lines += ["", "LINKS", *[f"  {k:<10}  {v}" for k, v in links.items()],
              "", "RECOVERY", f"  {RECOVERY[target['kind']]}",
              "", f"-- Argus SOAR, incident {env['incident_key']}"]

    return {
        "subject": f"[Argus] {env['severity']} contained: {scenario} on {target['name']}",
        "text": "\n".join(lines),
        "title": f"Contained: {scenario} ({env['severity']})",
        "color": ORANGE if env["severity"] in ("HIGH", "CRITICAL") else GREEN,
        "fields": [
            ("Target", target["arn"], False),
            ("Finding", guardduty_type(env["finding_type"]), True),
            ("Time to contain", duration(ttc), True),
            ("Actions", "\n".join(actions[:10]) or "none", False),
            ("Evidence", f"{pkg.get('package_uri', 'n/a')}\nSHA-256 {pkg.get('sha256', 'n/a')}", False),
            *[(k, v, False) for k, v in links.items()],
        ],
    }


def failure_message(state, links):
    env = state.get("envelope", {})
    target = env.get("target") or {}
    scenario = SCENARIO.get(env.get("playbook"), "Security incident")
    err = parse_error(state.get("error") or {})
    phase = failed_phase(state)
    done = remediation_lines(state)
    where = f"{err['code']}" + (f" (during {err['operation']})" if err["operation"] else "")

    lines = [
        "ARGUS REMEDIATION FAILED: MANUAL ACTION REQUIRED",
        "",
        f"{scenario} - severity {env.get('severity', 'unknown')}",
        f"Finding   {guardduty_type(env.get('finding_type', ''))}",
        f"Target    {target.get('arn', 'unknown')}",
        "",
        "WHAT WENT WRONG",
        f"  Failed step   {phase}",
        f"  Error         {where}",
        f"  Detail        {err['message']}",
        "",
        "COMPLETED BEFORE THE FAILURE",
        *([f"  - {line}" for line in done] or ["  no phase completed"]),
        f"  Steps inside {phase} may have partly run: check the target's current state.",
        "",
        "NEXT STEPS",
        "  1. Contain the target by hand if it is still exposed (see the actions above).",
        "  2. Open the execution to see the failing step's input and error.",
        "  3. Fix the cause. The incident is marked FAILED, so it runs again automatically",
        "     the next time GuardDuty updates the finding.",
        "",
        "LINKS",
        *[f"  {k:<10}  {v}" for k, v in links.items()],
        "",
        f"-- Argus SOAR, incident {env.get('incident_key', 'unknown')}",
    ]
    return {
        "subject": f"[Argus] FAILED: {scenario} on {target.get('name', 'unknown')} - action required",
        "text": "\n".join(lines),
        "title": f"Remediation FAILED: {scenario}",
        "color": RED,
        "fields": [
            ("Target", target.get("arn", "unknown"), False),
            ("Failed step", phase, True),
            ("Error", where, True),
            ("Detail", err["message"], False),
            ("Completed phases", "\n".join(done[:10]) or f"none ({phase} may have partly run; check the target)", False),
            *[(k, v, False) for k, v in links.items()],
        ],
    }


def warning_message(state, links):
    env = state.get("envelope", {})
    err = parse_error(state.get("late_error") or {})
    text = "\n".join([
        "ARGUS: LATE EVIDENCE COLLECTION FAILED (the incident was contained)",
        "",
        f"Incident  {env.get('incident_key', 'unknown')}",
        f"Error     {err['code']}: {err['message']}",
        "",
        *[f"{k:<10}  {v}" for k, v in links.items()],
    ])
    return {
        "subject": f"[Argus] Late evidence missing for incident {env.get('incident_key', 'unknown')}",
        "text": text,
        "title": "Late evidence collection failed (incident contained)",
        "color": ORANGE,
        "fields": [("Error", f"{err['code']}: {err['message']}", False),
                   *[(k, v, False) for k, v in links.items()]],
    }


# ================================================================ delivery

def post_webhook(msg) -> bool:
    param = os.environ.get("WEBHOOK_PARAM")
    if not param:
        return False
    url = au.get_ssm_parameter(param)
    if not url or url.strip().lower() == "disabled":
        log.info("webhook disabled")
        return False
    payload = {"embeds": [{
        "title": msg["title"][:256],
        "color": msg["color"],
        "fields": [{"name": n, "value": str(v)[:1024], "inline": inline} for n, v, inline in msg["fields"]][:25],
        "timestamp": au.now_iso(),
    }]}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "argus-soar"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - URL comes from our own SSM parameter
        log.info("webhook status %s", resp.status)
    return True


def write_runbook(state) -> str:
    env, pkg = state["envelope"], state.get("package") or {}
    timeline = [
        (env.get("finding_updated") or env.get("finding_created"), "Detected by GuardDuty"),
        (env.get("event_received"), "Received by Argus (EventBridge)"),
        ((state.get("evidence") or {}).get("completed_at"), "Evidence preserved"),
        ((state.get("containment") or {}).get("completed_at"), "Containment complete"),
        ((state.get("eradication") or {}).get("completed_at"), "Eradication complete"),
    ]
    lines = [
        f"# Incident Runbook - {env['incident_key']}",
        "",
        f"**{SCENARIO.get(env.get('playbook'), 'Incident')}** - severity {env['severity']} - "
        f"`{guardduty_type(env['finding_type'])}`",
        "",
        f"**Target:** `{env['target']['arn']}`",
        "",
        "## Timeline",
        *[f"- {hhmmss(t)} - {label}" for t, label in timeline],
        "",
        "## Actions taken",
        *[f"1. {line}" for line in remediation_lines(state)],
        "",
        "## Evidence",
        f"- Package: `{pkg.get('package_uri', 'n/a')}`",
        f"- SHA-256: `{pkg.get('sha256', 'n/a')}`",
        "- Verify: download `final_package.json` and `sha256.txt`, then `sha256sum -c sha256.txt`",
        "",
        "## Recovery",
        RECOVERY[env["target"]["kind"]],
        "",
    ]
    key = f"runbooks/{env['incident_key']}.md"
    return au.put_bytes(os.environ["EVIDENCE_BUCKET"], key, "\n".join(lines).encode(), "text/markdown")
