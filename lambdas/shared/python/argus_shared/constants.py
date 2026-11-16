"""Names and values shared by all Argus functions."""

MANAGED_TAG_KEY = "argus:managed"
MANAGED_TAG_VALUE = "true"
STATUS_TAG_KEY = "argus:status"
INCIDENT_TAG_KEY = "argus:incident_key"
QUARANTINE_TIME_TAG_KEY = "argus:quarantine_time"
QUARANTINED = "QUARANTINED"

SIM_NAME_PREFIX = "argus-sim-"

DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"
REVOKE_SESSIONS_POLICY_NAME = "ArgusRevokeOlderSessions"

SEVERITY_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ASFF resource types per target kind.
RESOURCE_TYPE_FOR_KIND = {
    "iam_user": "AwsIamAccessKey",
    "ec2_instance": "AwsEc2Instance",
    "s3_bucket": "AwsS3Bucket",
}

# Each state machine is told which playbook it runs via the PLAYBOOK env var.
KIND_FOR_PLAYBOOK = {"iam": "iam_user", "ec2": "ec2_instance", "s3": "s3_bucket"}
