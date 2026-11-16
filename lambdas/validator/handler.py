"""ValidateFinding: build the incident envelope and re-check scope.

Pure function: no AWS calls, so its role needs nothing beyond logging.
The DynamoDB idempotency writes happen next, as direct Step Functions integrations:
  RecordIncident  - one item per finding (the same finding is never handled twice)
  LockResource    - one lock per target resource (different findings about the SAME
                    resource, e.g. GuardDuty's one-finding-per-domain for mining DNS
                    lookups, don't run concurrent playbooks against it)
The lock's expiry is computed here because ASL has no date arithmetic.

Input (from the state machine):
  {"playbook": "iam" | "ec2" | "s3", "finding": <EventBridge input transformer output>}

Env:
  SIM_INSTANCE_IDS     comma-separated simulation instance IDs (EC2 scope)
  RESOURCE_LOCK_MINUTES  how long a resource stays claimed by one incident (default 60)
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from argus_shared.envelope import build_envelope, check_scope

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, _context):
    playbook = event["playbook"]
    raw = event["finding"]
    sim_ids = {i.strip() for i in os.environ.get("SIM_INSTANCE_IDS", "").split(",") if i.strip()}

    envelope = build_envelope(raw, playbook)
    check_scope(envelope, sim_ids)

    minutes = int(os.environ.get("RESOURCE_LOCK_MINUTES", "60"))
    lock_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    # Same ISO-8601 shape as $$.State.EnteredTime, so DynamoDB can compare them as strings.
    envelope["resource_lock"] = {
        "key": f"lock#{envelope['target']['arn']}",
        "until": lock_until.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }

    log.info(json.dumps({"msg": "finding accepted", "incident_key": envelope["incident_key"],
                         "finding_type": envelope["finding_type"], "target": envelope["target"]}))
    return envelope
