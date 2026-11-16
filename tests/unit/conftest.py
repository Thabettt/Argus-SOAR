import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambdas" / "shared" / "python"))

# Never let tests reach a real account.
os.environ.update({
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_REGION": "us-east-1",
    # moto only knows AWS managed policies (AWSDenyAll) when asked to load them.
    "MOTO_IAM_LOAD_MANAGED_POLICIES": "true",
})
os.environ.pop("AWS_PROFILE", None)

ACCOUNT = "123456789012"  # moto's default account


def load_handler(relative: str):
    """Every Lambda file is called handler.py, so load each under a unique module name."""
    path = ROOT / "lambdas" / relative / "handler.py"
    name = "handler_" + relative.replace("/", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_event(name: str) -> dict:
    return json.loads((ROOT / "tests" / "events" / name).read_text())


@pytest.fixture(autouse=True)
def aws():
    """Every test runs inside moto, including its fixtures (which run before the test body)."""
    from moto import mock_aws

    with mock_aws():
        yield


@pytest.fixture
def remediation_role():
    """An assumable role in moto (moto doesn't enforce IAM, so permissions are not tested here)."""
    import boto3

    iam = boto3.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName="argus-remediation-role", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    os.environ["REMEDIATION_ROLE_ARN"] = arn
    os.environ["FORENSICS_ROLE_ARN"] = arn
    return arn
