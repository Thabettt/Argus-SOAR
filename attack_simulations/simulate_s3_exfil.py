"""Simulation 3 - S3 data exfiltration / public exposure.

1. (operator) Turns off the simulation bucket's Block Public Access.
   -> Policy:S3/BucketBlockPublicAccessDisabled (LOW)
2. Asks you to switch to the threat-list VPN, then (as argus-sim-exfil, using its key
   from SSM) lists and downloads every object several times - the exfiltration pattern.
   -> Discovery:S3/MaliciousIPCaller.Custom (HIGH)
3. Optional --public-demo: applies a public-read bucket policy. Only works if the
   ACCOUNT-level Block Public Access is off, which affects every bucket in the account -
   turn it off on purpose, only for the demo, and back on right after.
   -> also fires the Config rule s3-bucket-public-read-prohibited
"""

import argparse
import json

from botocore.exceptions import ClientError

from common import banner, operator_session, pause_for_vpn, sim_user_session, tf_outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=5, help="download rounds (default 5)")
    parser.add_argument("--public-demo", action="store_true", help="also try to make the bucket public")
    args = parser.parse_args()

    out = tf_outputs()
    region, bucket = out["region"], out["sim_data_bucket"]
    operator = operator_session(region)

    banner(f"Step 1 - turning off Block Public Access on {bucket}")
    operator.client("s3").put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    print("  bucket-level Block Public Access is OFF (account-level setting untouched)")

    if args.public_demo:
        banner("Step 1b - public-read policy (optional demo)")
        policy = {"Version": "2012-10-17", "Statement": [{
            "Sid": "ArgusSimPublicRead", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}
        try:
            operator.client("s3").put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
            print("  bucket is now PUBLIC - Argus should close it shortly")
        except ClientError as exc:
            print(f"  refused ({exc.response['Error']['Code']}): account-level Block Public Access is on. "
                  "That's the safe default; the GuardDuty findings don't need a public bucket.")

    pause_for_vpn()

    banner("Step 2 - bulk reads from the threat-list IP as argus-sim-exfil")
    s3 = sim_user_session(operator, out["sim_exfil_key_parameter"], region).client("s3")
    total = 0
    for i in range(args.rounds):
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
        for key in keys:
            s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            total += 1
        print(f"  round {i + 1}: listed and downloaded {len(keys)} objects")
    print(f"\nDone: {total} downloads. Watch for the findings, then the argus-s3-playbook execution.")
    print("Re-running? First: python attack_simulations/reset_simulation.py --s3")


if __name__ == "__main__":
    main()
