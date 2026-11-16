import pytest
from conftest import load_event

from argus_shared.envelope import (
    EnvelopeError,
    OutOfScope,
    build_envelope,
    check_scope,
    incident_key_for,
)


def test_iam_envelope_normalizes_target():
    env = build_envelope(load_event("iam_transformer_input.json"), "iam")
    assert env["target"] == {
        "kind": "iam_user",
        "id": "argus-sim-backdoor",
        "name": "argus-sim-backdoor",
        "arn": "arn:aws:iam::111122223333:user/argus-sim-backdoor",
        "access_key_id": "AKIAEXAMPLEKEY000001",
    }
    assert env["incident_id"] == env["finding_id"]
    assert env["severity"] == "MEDIUM"


def test_incident_key_comes_from_finding_id_not_event_id():
    raw = load_event("iam_transformer_input.json")
    first = build_envelope(raw, "iam")
    raw["event_id"] = "a-different-delivery-of-the-same-finding"
    second = build_envelope(raw, "iam")
    assert first["incident_key"] == second["incident_key"] == incident_key_for(raw["finding_id"])
    assert len(first["incident_key"]) == 16


def test_ec2_envelope():
    env = build_envelope(load_event("ec2_transformer_input.json"), "ec2")
    assert env["target"]["id"] == "i-0123456789abcdef0"
    assert env["target"]["arn"].endswith(":instance/i-0123456789abcdef0")


def test_s3_envelope_includes_actor():
    env = build_envelope(load_event("s3_transformer_input.json"), "s3")
    assert env["target"]["name"] == "argus-sim-data-test"
    assert env["actor"] == {"user_name": "argus-sim-exfil", "access_key_id": "AKIAEXAMPLEKEY000002"}


def test_missing_fields_rejected():
    raw = load_event("iam_transformer_input.json")
    del raw["product_arn"]
    with pytest.raises(EnvelopeError, match="product_arn"):
        build_envelope(raw, "iam")


def test_wrong_resource_type_rejected():
    with pytest.raises(EnvelopeError):
        build_envelope(load_event("ec2_transformer_input.json"), "s3")


def test_scope_accepts_sim_resources():
    check_scope(build_envelope(load_event("iam_transformer_input.json"), "iam"), set())
    check_scope(build_envelope(load_event("s3_transformer_input.json"), "s3"), set())
    check_scope(build_envelope(load_event("ec2_transformer_input.json"), "ec2"), {"i-0123456789abcdef0"})


@pytest.mark.parametrize("fixture,playbook,mutate", [
    ("iam_transformer_input.json", "iam",
     lambda r: r["resources"][0]["Details"]["AwsIamAccessKey"].update(PrincipalName="prod-admin")),
    ("s3_transformer_input.json", "s3",
     lambda r: r["resources"][0].update(Id="arn:aws:s3:::company-customer-data")),
])
def test_scope_rejects_real_resources(fixture, playbook, mutate):
    raw = load_event(fixture)
    mutate(raw)
    with pytest.raises(OutOfScope):
        check_scope(build_envelope(raw, playbook), set())


def test_scope_rejects_unknown_instance():
    env = build_envelope(load_event("ec2_transformer_input.json"), "ec2")
    with pytest.raises(OutOfScope):
        check_scope(env, {"i-someotherinstance"})
