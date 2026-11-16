"""Helpers shared by the Argus simulation scripts.

The scripts run with YOUR operator credentials (default AWS profile or AWS_PROFILE),
except where they deliberately switch to a simulation user's leaked key.
Resource names come from `terraform output -json`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]


def tf_outputs() -> dict:
    """Read Terraform outputs (set TERRAFORM_BIN if terraform isn't on PATH,
    or ARGUS_OUTPUTS_JSON to a file produced by `terraform output -json`)."""
    cached = os.environ.get("ARGUS_OUTPUTS_JSON")
    if cached:
        raw = json.loads(Path(cached).read_text())
    else:
        tf = os.environ.get("TERRAFORM_BIN") or shutil.which("terraform")
        if not tf:
            sys.exit("terraform not found: set TERRAFORM_BIN or ARGUS_OUTPUTS_JSON")
        out = subprocess.run([tf, f"-chdir={ROOT / 'terraform'}", "output", "-json"],
                             check=True, capture_output=True, text=True).stdout
        raw = json.loads(out)
    return {k: v["value"] for k, v in raw.items()}


def operator_session(region: str) -> boto3.Session:
    return boto3.Session(region_name=region)


def sim_user_session(operator: boto3.Session, parameter: str, region: str) -> boto3.Session:
    """A session using a simulation user's 'leaked' access key from SSM."""
    value = operator.client("ssm").get_parameter(Name=parameter, WithDecryption=True)["Parameter"]["Value"]
    creds = json.loads(value)
    return boto3.Session(aws_access_key_id=creds["access_key_id"],
                         aws_secret_access_key=creds["secret_access_key"], region_name=region)


def public_ip() -> str:
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
            return resp.read().decode().strip()
    except OSError:
        return "unknown"


def pause_for_vpn(threat_ip_hint: str = "") -> None:
    print(f"\nYour current public IP is {public_ip()}.")
    print("Switch to the VPN/proxy whose egress IP is in threat_list_ips" + (f" ({threat_ip_hint})" if threat_ip_hint else "") + ".")
    input("Press Enter once connected... ")
    print(f"Public IP is now {public_ip()}.\n")


def banner(text: str) -> None:
    print("\n" + "=" * 70 + f"\n  {text}\n" + "=" * 70)
