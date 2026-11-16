"""AWS helpers shared by the Argus Lambdas."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Standard retry mode backs off on throttling (LookupEvents allows ~2 req/s).
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 8})


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    """Parse the ISO-8601 timestamps EventBridge, ASFF and Argus produce."""
    value = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def seconds_between(start: str, end: str) -> float:
    return round((parse_iso(end) - parse_iso(start)).total_seconds(), 3)


def client(service: str, session: boto3.Session | None = None):
    return (session or boto3).client(service, config=BOTO_CONFIG)


def assume_role(role_arn: str, incident_key: str) -> boto3.Session:
    """Assume an app-side role. The session name ties every CloudTrail entry to the incident."""
    creds = client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"argus-{incident_key}",
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
    )


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


# ---------------------------------------------------------------- evidence

def canonical_json(obj: Any) -> bytes:
    """One exact byte representation, so a digest can be recomputed from the stored file."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evidence_key(incident_key: str, name: str) -> str:
    return f"evidence/{incident_key}/{name}"


def put_bytes(bucket: str, key: str, body: bytes, content_type: str, s3=None) -> str:
    """Write to the evidence bucket with SSE-KMS.

    Object Lock buckets reject PUTs without an integrity checksum, so one is always sent.
    """
    s3 = s3 or client("s3")
    kwargs: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "Body": body,
        "ContentType": content_type,
        "ChecksumAlgorithm": "SHA256",
    }
    kms_key = os.environ.get("EVIDENCE_KMS_KEY_ARN")
    if kms_key:
        kwargs["ServerSideEncryption"] = "aws:kms"
        kwargs["SSEKMSKeyId"] = kms_key
    s3.put_object(**kwargs)
    return f"s3://{bucket}/{key}"


def put_json(bucket: str, key: str, data: Any, s3=None) -> str:
    return put_bytes(bucket, key, canonical_json(data), "application/json", s3=s3)


def get_json(bucket: str, key: str, s3=None) -> Any | None:
    s3 = s3 or client("s3")
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        if error_code(exc) in ("NoSuchKey", "404"):
            return None
        raise
    return json.loads(body)


def get_ssm_parameter(name: str, decrypt: bool = True) -> str:
    return client("ssm").get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]


# ---------------------------------------------------------------- CloudTrail

def lookup_management_events(
    attribute_key: str,
    attribute_value: str,
    start: datetime,
    end: datetime,
    session: boto3.Session | None = None,
    max_events: int = 500,
) -> list[dict]:
    """LookupEvents returns management events only, and lags 5-15 minutes behind real time."""
    ct = client("cloudtrail", session)
    paginator = ct.get_paginator("lookup_events")
    events: list[dict] = []
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": attribute_key, "AttributeValue": attribute_value}],
        StartTime=start,
        EndTime=end,
    ):
        for raw in page.get("Events", []):
            events.append(summarize_trail_event(raw))
            if len(events) >= max_events:
                return events
    return events


def summarize_trail_event(raw: dict) -> dict:
    detail = {}
    try:
        detail = json.loads(raw.get("CloudTrailEvent") or "{}")
    except json.JSONDecodeError:
        pass
    return {
        "event_time": str(raw.get("EventTime")),
        "event_name": raw.get("EventName"),
        "event_source": raw.get("EventSource"),
        "source_ip": detail.get("sourceIPAddress"),
        "user_agent": detail.get("userAgent"),
        "error_code": detail.get("errorCode"),
        "request_parameters": detail.get("requestParameters"),
    }


# ---------------------------------------------------------------- tags

def has_managed_tag(tags: Iterable[dict]) -> bool:
    from .constants import MANAGED_TAG_KEY, MANAGED_TAG_VALUE

    return any(t.get("Key") == MANAGED_TAG_KEY and t.get("Value") == MANAGED_TAG_VALUE for t in tags)


def revoke_older_sessions_policy(issued_before: str) -> str:
    """Deny every session issued before `issued_before` (the console's 'Revoke active sessions')."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": issued_before}},
                }
            ],
        }
    )
