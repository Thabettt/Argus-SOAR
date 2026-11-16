"""Finalize: mark the incident COMPLETE and the Security Hub finding RESOLVED.

The "Imported" event Security Hub sends for this update is dropped by the EventBridge
rules' Workflow.Status = NEW filter. Chained incidents (started by another playbook)
have a synthetic finding ID, so they skip the Security Hub update.

Env: INCIDENTS_TABLE
"""

from __future__ import annotations

import logging
import os

from argus_shared import aws_utils as au

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, _context):
    state = event["state"]
    envelope = state["envelope"]
    package = state.get("package") or {}

    au.client("dynamodb").update_item(
        TableName=os.environ["INCIDENTS_TABLE"],
        Key={"finding_id": {"S": envelope["occurrence_id"]}},
        UpdateExpression="SET #s = :c, completed_at = :t, evidence_uri = :u, evidence_sha256 = :h, "
                         "time_to_contain_seconds = :ttc",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":c": {"S": "COMPLETE"},
            ":t": {"S": au.now_iso()},
            ":u": {"S": package.get("package_uri", "")},
            ":h": {"S": package.get("sha256", "")},
            ":ttc": {"N": str(package.get("time_to_contain_seconds") or 0)},
        },
    )

    resolved = False
    if not envelope.get("chained_from"):
        resp = au.client("securityhub").batch_update_findings(
            FindingIdentifiers=[{"Id": envelope["finding_id"], "ProductArn": envelope["product_arn"]}],
            Workflow={"Status": "RESOLVED"},
            Note={"Text": f"Contained by Argus - incident {envelope['incident_key']}. "
                          f"Evidence: {package.get('package_uri', 'n/a')}",
                  "UpdatedBy": "argus-soar"},
        )
        if resp.get("UnprocessedFindings"):
            raise RuntimeError(f"Security Hub did not update the finding: {resp['UnprocessedFindings']}")
        resolved = True

    return {"status": "COMPLETE", "securityhub_resolved": resolved, "completed_at": au.now_iso()}
