"""Generate GuardDuty SAMPLE findings to test routing (Phase 3).

Sample findings point at fake resources, so the scoped Argus rules will NOT match
them. Use them with a temporary, unscoped rule (or EventBridge's test-event-pattern
with a captured event) to check that the Types wildcards match; use the real
simulations for end-to-end tests.
"""

import argparse

from common import operator_session, tf_outputs

TYPES = [
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "Discovery:S3/MaliciousIPCaller.Custom",
    "Policy:S3/BucketBlockPublicAccessDisabled",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--type", action="append", choices=TYPES, help="finding type (repeatable; default all)")
    args = parser.parse_args()

    out = tf_outputs()
    gd = operator_session(out["region"]).client("guardduty")
    types = args.type or TYPES
    gd.create_sample_findings(DetectorId=out["guardduty_detector_id"], FindingTypes=types)
    print("Created sample findings:\n  " + "\n  ".join(types))


if __name__ == "__main__":
    main()
