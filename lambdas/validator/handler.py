"""ValidateFinding: build the incident envelope and re-check scope.

Pure function: no AWS calls, so its role needs nothing beyond logging.
The DynamoDB idempotency write happens next, as a direct Step Functions integration.

Input (from the state machine):
  {"playbook": "iam" | "ec2" | "s3", "finding": <EventBridge input transformer output>}

Env:
  SIM_INSTANCE_IDS  comma-separated simulation instance IDs (EC2 scope)
"""

import json
import logging
import os

from argus_shared.envelope import build_envelope, check_scope

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, _context):
    playbook = event["playbook"]
    raw = event["finding"]
    sim_ids = {i.strip() for i in os.environ.get("SIM_INSTANCE_IDS", "").split(",") if i.strip()}

    envelope = build_envelope(raw, playbook)
    check_scope(envelope, sim_ids)

    log.info(json.dumps({"msg": "finding accepted", "incident_key": envelope["incident_key"],
                         "finding_type": envelope["finding_type"], "target": envelope["target"]}))
    return envelope
