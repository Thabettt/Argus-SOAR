"""The incident envelope: the one contract every Argus Lambda is built around.

The EventBridge input transformer forwards a trimmed Security Hub (ASFF) finding.
`build_envelope` validates it and adds a normalized `target`, so playbooks never
parse ASFF resource details themselves.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .constants import KIND_FOR_PLAYBOOK, RESOURCE_TYPE_FOR_KIND, SIM_NAME_PREFIX

REQUIRED_FIELDS = (
    "finding_id",
    "product_arn",
    "event_id",
    "event_received",
    "finding_type",
    "severity",
    "finding_created",
    "account",
    "region",
    "resources",
)


class EnvelopeError(Exception):
    """The input isn't a finding Argus can handle."""


class OutOfScope(Exception):
    """The finding targets a resource Argus must never touch."""


def incident_key_for(finding_id: str) -> str:
    """Short, S3-safe key derived from the finding ID (finding IDs contain '/' and ':')."""
    return hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:16]


def build_envelope(raw: dict[str, Any], playbook: str) -> dict[str, Any]:
    missing = [f for f in REQUIRED_FIELDS if raw.get(f) in (None, "")]
    if missing:
        raise EnvelopeError(f"missing fields: {', '.join(missing)}")
    if playbook not in KIND_FOR_PLAYBOOK:
        raise EnvelopeError(f"unknown playbook {playbook!r}")

    resources = raw["resources"]
    if isinstance(resources, dict):
        resources = [resources]

    kind = KIND_FOR_PLAYBOOK[playbook]
    target = _target_from_resources(kind, resources, raw["account"], raw["region"])

    envelope = {
        "incident_id": raw["finding_id"],
        "incident_key": incident_key_for(raw["finding_id"]),
        "finding_id": raw["finding_id"],
        "product_arn": raw["product_arn"],
        "event_id": raw["event_id"],
        "event_received": raw["event_received"],
        "finding_type": raw["finding_type"],
        "severity": str(raw["severity"]).upper(),
        "finding_created": raw["finding_created"],
        "account": raw["account"],
        "region": raw["region"],
        "playbook": playbook,
        "target": target,
        "actor": _actor_from_resources(resources) if playbook == "s3" else None,
        "chained_from": raw.get("chained_from"),
    }
    return envelope


def check_scope(envelope: dict[str, Any], sim_instance_ids: set[str]) -> None:
    """Defense in depth: EventBridge patterns already scope; this re-checks in code."""
    target = envelope["target"]
    kind = target["kind"]
    if kind in ("iam_user", "s3_bucket"):
        if not target["name"].startswith(SIM_NAME_PREFIX):
            raise OutOfScope(f"{kind} {target['name']!r} is not an Argus simulation resource")
    elif kind == "ec2_instance":
        if target["id"] not in sim_instance_ids:
            raise OutOfScope(f"instance {target['id']!r} is not an Argus simulation instance")
    else:  # pragma: no cover - build_envelope only produces the kinds above
        raise OutOfScope(f"unknown target kind {kind!r}")


# ---------------------------------------------------------------- internals

def _find_resource(resources: list[dict], resource_type: str) -> dict | None:
    for res in resources:
        if res.get("Type") == resource_type:
            return res
    return None


def _target_from_resources(kind: str, resources: list[dict], account: str, region: str) -> dict:
    res = _find_resource(resources, RESOURCE_TYPE_FOR_KIND[kind])
    if res is None:
        raise EnvelopeError(f"no {RESOURCE_TYPE_FOR_KIND[kind]} resource in finding")

    if kind == "iam_user":
        details = (res.get("Details") or {}).get("AwsIamAccessKey") or {}
        name = details.get("PrincipalName") or details.get("UserName")
        if not name:
            raise EnvelopeError("IAM finding has no PrincipalName/UserName")
        access_key_id = str(res.get("Id", "")).split(":")[-1] or None
        return {
            "kind": kind,
            "id": name,
            "name": name,
            "arn": f"arn:aws:iam::{account}:user/{name}",
            "access_key_id": access_key_id,
        }

    if kind == "ec2_instance":
        arn = str(res.get("Id", ""))
        instance_id = arn.split("/")[-1]
        if not instance_id.startswith("i-"):
            raise EnvelopeError(f"unexpected EC2 resource id {arn!r}")
        if not arn.startswith("arn:"):
            arn = f"arn:aws:ec2:{region}:{account}:instance/{instance_id}"
        return {"kind": kind, "id": instance_id, "name": instance_id, "arn": arn}

    # s3_bucket
    arn = str(res.get("Id", ""))
    name = arn.split(":::")[-1]
    if not name:
        raise EnvelopeError(f"unexpected S3 resource id {arn!r}")
    return {"kind": kind, "id": name, "name": name, "arn": f"arn:aws:s3:::{name}"}


def _actor_from_resources(resources: list[dict]) -> dict | None:
    """For S3 findings, the IAM principal that made the calls (used for IAM chaining)."""
    res = _find_resource(resources, "AwsIamAccessKey")
    if not res:
        return None
    details = (res.get("Details") or {}).get("AwsIamAccessKey") or {}
    name = details.get("PrincipalName") or details.get("UserName")
    if not name:
        return None
    return {"user_name": name, "access_key_id": str(res.get("Id", "")).split(":")[-1] or None}
