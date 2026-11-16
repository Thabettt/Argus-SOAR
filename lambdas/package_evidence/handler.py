"""PackageEvidence: build the final bundle, hash it, store it under Object Lock.

The bundle is serialized canonically (sorted keys, fixed separators) and those exact
bytes are stored, so anyone can verify with `sha256sum final_package.json`.

Env: EVIDENCE_BUCKET, EVIDENCE_KMS_KEY_ARN
"""

from __future__ import annotations

import logging
import os

from argus_shared import aws_utils as au

log = logging.getLogger()
log.setLevel(logging.INFO)


def build_bundle(state: dict, pre_containment: dict | None) -> dict:
    envelope = state["envelope"]
    containment = state.get("containment") or {}
    eradication = state.get("eradication") or {}
    evidence = state.get("evidence") or {}

    actions = []
    for phase in (evidence, containment, eradication):
        for action in phase.get("actions", []):
            actions.append({"phase": phase.get("phase"), **action})

    # Detection is measured from THIS occurrence: for a recurring finding, GuardDuty's
    # UpdatedAt, not when the finding was first created.
    observed = envelope.get("finding_updated") or envelope["finding_created"]
    timestamps = {
        "finding_created": envelope["finding_created"],
        "finding_updated": observed,
        "event_received": envelope["event_received"],
        "evidence_start": evidence.get("started_at"),
        "containment_start": containment.get("started_at"),
        "containment_complete": containment.get("completed_at"),
        "eradication_complete": eradication.get("completed_at"),
    }
    if containment.get("completed_at"):
        timestamps["time_to_contain_seconds"] = au.seconds_between(
            envelope["event_received"], containment["completed_at"])
    timestamps["detection_latency_seconds"] = au.seconds_between(observed, envelope["event_received"])

    return {
        "schema": "argus.evidence.v1",
        "incident_id": envelope["incident_id"],
        "incident_key": envelope["incident_key"],
        "finding_type": envelope["finding_type"],
        "severity": envelope["severity"],
        "playbook": envelope["playbook"],
        "target": envelope["target"],
        "chained_from": envelope.get("chained_from"),
        "pre_containment": pre_containment,
        "remediation_actions": actions,
        "timestamps": timestamps,
    }


def lambda_handler(event, _context):
    state = event["state"]
    key = state["envelope"]["incident_key"]
    bucket = os.environ["EVIDENCE_BUCKET"]

    pre = au.get_json(bucket, au.evidence_key(key, "pre_containment.json"))
    bundle = build_bundle(state, pre)
    body = au.canonical_json(bundle)
    digest = au.sha256_hex(body)

    package_uri = au.put_bytes(bucket, au.evidence_key(key, "final_package.json"), body, "application/json")
    # sha256sum-compatible line: "<digest>  <filename>"
    au.put_bytes(bucket, au.evidence_key(key, "sha256.txt"),
                 f"{digest}  final_package.json\n".encode(), "text/plain")

    log.info("packaged %s sha256=%s", package_uri, digest)
    return {
        "package_uri": package_uri,
        "sha256": digest,
        "time_to_contain_seconds": bundle["timestamps"].get("time_to_contain_seconds"),
        "detection_latency_seconds": bundle["timestamps"]["detection_latency_seconds"],
        "action_count": len(bundle["remediation_actions"]),
    }
