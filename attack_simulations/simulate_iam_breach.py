"""Simulation 1 - IAM credential compromise.

1. Reads the "leaked" access key of argus-sim-backdoor from SSM (the simulated .env file).
2. Makes normal-looking calls from your normal IP.
3. Asks you to switch to the VPN whose IP is on the GuardDuty threat list, then makes
   calls the user isn't allowed to make (iam:CreateUser, ec2:DescribeInstances).
   They fail with AccessDenied - that's fine, CloudTrail logs denied calls too, and the
   source IP is what triggers the finding.

Expected: UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom (MEDIUM) within ~5-15 min,
then the argus-iam-playbook execution in Step Functions.
"""

import time

from botocore.exceptions import ClientError

from common import banner, operator_session, pause_for_vpn, sim_user_session, tf_outputs


def attempt(label, fn):
    try:
        fn()
        print(f"  ok      {label}")
    except ClientError as exc:
        print(f"  denied  {label} ({exc.response['Error']['Code']})")


def main():
    out = tf_outputs()
    region = out["region"]
    operator = operator_session(region)
    attacker = sim_user_session(operator, out["sim_backdoor_key_parameter"], region)
    s3, iam, ec2 = attacker.client("s3"), attacker.client("iam"), attacker.client("ec2")

    banner("Phase 1 - normal activity from your usual IP")
    attempt("s3:ListBuckets", s3.list_buckets)
    attempt("iam:GetUser", iam.get_user)

    pause_for_vpn()

    banner("Phase 2 - suspicious activity from the threat-list IP")
    for _ in range(3):
        attempt("s3:ListBuckets", s3.list_buckets)
        attempt("iam:GetUser", iam.get_user)
        attempt("iam:CreateUser (privilege escalation attempt)", lambda: iam.create_user(UserName="argus-sim-evil"))
        attempt("ec2:DescribeInstances (discovery)", ec2.describe_instances)
        time.sleep(2)

    print("\nDone. Watch for the finding in GuardDuty/Security Hub, then the argus-iam-playbook execution.")
    print("Re-running? First: python attack_simulations/reset_simulation.py --iam")


if __name__ == "__main__":
    main()
