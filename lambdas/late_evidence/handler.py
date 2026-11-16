"""CollectLateEvidence: runs ~15 minutes after Notify, outside the containment path.

CloudTrail (5-15 min) and VPC Flow Logs (~10 min) arrive late, so the fast forensics
step can't see the most recent activity. This step collects it and writes
supplemental.json with its own digest - the already-hashed final package is never changed.

  iam_user      LookupEvents for the full window
  ec2_instance  CloudWatch Logs Insights over the Flow Logs group, filtered by the ENIs
  s3_bucket     Athena over the CloudTrail table: S3 data events for the bucket

Env: FORENSICS_ROLE_ARN, EVIDENCE_BUCKET, EVIDENCE_KMS_KEY_ARN, FLOW_LOG_GROUP,
     ATHENA_WORKGROUP, ATHENA_DATABASE, ATHENA_TABLE, WINDOW_BEFORE_MINUTES (default 120)
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone

from argus_shared import aws_utils as au

log = logging.getLogger()
log.setLevel(logging.INFO)

POLL_SECONDS = 3
MAX_WAIT_SECONDS = 240
MAX_ROWS = 1000
SAFE_NAME = re.compile(r"^[a-z0-9.\-]{3,63}$")


def lambda_handler(event, _context):
    state = event["state"]
    envelope = state["envelope"]
    key = envelope["incident_key"]
    kind = envelope["target"]["kind"]

    end = datetime.now(timezone.utc)
    start = au.parse_iso(envelope["finding_created"]) - timedelta(
        minutes=int(os.environ.get("WINDOW_BEFORE_MINUTES", "120")))

    if kind == "iam_user":
        session = au.assume_role(os.environ["FORENSICS_ROLE_ARN"], key)
        data = {"cloudtrail_management_events": au.lookup_management_events(
            "Username", envelope["target"]["name"], start, end, session=session, max_events=2000)}
    elif kind == "ec2_instance":
        enis = [e["eni_id"] for e in ((state.get("evidence") or {}).get("summary") or {}).get("enis", [])]
        data = {"flow_logs": flow_logs(enis, start, end)}
    else:
        data = {"s3_data_events": s3_data_events(envelope["target"]["name"], start, end)}

    document = {
        "incident_id": envelope["incident_id"],
        "incident_key": key,
        "collected_at": au.now_iso(),
        "window": {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
        **data,
    }
    body = au.canonical_json(document)
    digest = au.sha256_hex(body)
    bucket = os.environ["EVIDENCE_BUCKET"]
    uri = au.put_bytes(bucket, au.evidence_key(key, "supplemental.json"), body, "application/json")
    au.put_bytes(bucket, au.evidence_key(key, "supplemental.sha256"),
                 f"{digest}  supplemental.json\n".encode(), "text/plain")
    return {"supplemental_uri": uri, "sha256": digest}


def flow_logs(eni_ids, start, end):
    if not eni_ids:
        return {"rows": [], "note": "no network interfaces recorded"}
    logs = au.client("logs")
    eni_list = ", ".join(f"'{e}'" for e in eni_ids if re.fullmatch(r"eni-[0-9a-f]+", e))
    query = (f"fields @timestamp, interfaceId, srcAddr, srcPort, dstAddr, dstPort, protocol, action, bytes "
             f"| filter interfaceId in [{eni_list}] | sort @timestamp asc | limit {MAX_ROWS}")
    qid = logs.start_query(logGroupName=os.environ["FLOW_LOG_GROUP"], startTime=int(start.timestamp()),
                           endTime=int(end.timestamp()), queryString=query)["queryId"]
    waited = 0
    while waited < MAX_WAIT_SECONDS:
        resp = logs.get_query_results(queryId=qid)
        if resp["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(POLL_SECONDS)
        waited += POLL_SECONDS
    if resp["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query ended with status {resp['status']}")
    rows = [{f["field"]: f["value"] for f in row if not f["field"].startswith("@ptr")} for row in resp["results"]]
    return {"query": query, "rows": rows}


def s3_data_events(bucket, start, end):
    if not SAFE_NAME.fullmatch(bucket):
        raise ValueError(f"refusing to build a query for bucket name {bucket!r}")
    athena = au.client("athena")
    table = f"{os.environ['ATHENA_DATABASE']}.{os.environ['ATHENA_TABLE']}"
    query = f"""
        SELECT eventtime, eventname, sourceipaddress, useridentity.arn AS principal_arn,
               json_extract_scalar(requestparameters, '$.key') AS object_key, errorcode
        FROM {table}
        WHERE eventsource = 's3.amazonaws.com'
          AND json_extract_scalar(requestparameters, '$.bucketName') = '{bucket}'
          AND eventtime >= '{start.strftime("%Y-%m-%dT%H:%M:%SZ")}'
          AND timestamp >= '{start.strftime("%Y/%m/%d")}'
        ORDER BY eventtime
        LIMIT {MAX_ROWS}
    """
    qid = athena.start_query_execution(QueryString=query, WorkGroup=os.environ["ATHENA_WORKGROUP"])[
        "QueryExecutionId"]
    waited = 0
    while waited < MAX_WAIT_SECONDS:
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        if status["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(POLL_SECONDS)
        waited += POLL_SECONDS
    if status["State"] != "SUCCEEDED":
        raise RuntimeError(f"Athena query {qid} ended {status['State']}: {status.get('StateChangeReason')}")

    rows, header = [], None
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            values = [c.get("VarCharValue") for c in row["Data"]]
            if header is None:
                header = values
                continue
            rows.append(dict(zip(header, values)))
    return {"query_execution_id": qid, "query": " ".join(query.split()), "rows": rows}
