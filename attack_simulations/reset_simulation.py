"""Undo Argus's containment on the SIMULATION resources, to re-run a scenario or before
`terraform destroy` (a user with AWSDenyAll attached, or a bucket with the quarantine
policy, can block Terraform).

Only touches resources from the Terraform outputs (argus-sim-*). Evidence is never
deleted; forensic snapshots only with --delete-snapshots.

  python attack_simulations/reset_simulation.py --all
  python attack_simulations/reset_simulation.py --ec2 --start-instance
"""

import argparse

from botocore.exceptions import ClientError

from common import banner, operator_session, tf_outputs

DENY_ALL = "arn:aws:iam::aws:policy/AWSDenyAll"
REVOKE_POLICY = "ArgusRevokeOlderSessions"
ARGUS_TAGS = ["argus:status", "argus:incident_key", "argus:quarantine_time"]


def ignore(codes, fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise
        return None


def release_lock(session, out, resource_arn):
    """Recovery closes the incident: free the resource so a new attack is a new incident."""
    session.client("dynamodb").delete_item(TableName=out["incidents_table"],
                                           Key={"finding_id": {"S": f"lock#{resource_arn}"}})
    print(f"  resource lock released for {resource_arn}")


def reset_user(iam, user):
    ignore({"NoSuchEntity"}, iam.detach_user_policy, UserName=user, PolicyArn=DENY_ALL)
    for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Active")
    iam.untag_user(UserName=user, TagKeys=ARGUS_TAGS)
    print(f"  {user}: AWSDenyAll detached, keys re-activated, Argus tags removed")


def reset_role(iam, role):
    ignore({"NoSuchEntity"}, iam.delete_role_policy, RoleName=role, PolicyName=REVOKE_POLICY)
    print(f"  role {role}: {REVOKE_POLICY} removed (if present)")


def reset_iam(session, out):
    banner("IAM")
    iam = session.client("iam")
    account = session.client("sts").get_caller_identity()["Account"]
    for user in (out["sim_backdoor_user"], out["sim_exfil_user"]):
        reset_user(iam, user)
        release_lock(session, out, f"arn:aws:iam::{account}:user/{user}")
    reset_role(iam, out["sim_instance_role_name"])


def reset_ec2(session, out, start, delete_snapshots):
    banner("EC2")
    ec2 = session.client("ec2")
    iid = out["sim_instance_id"]
    instance = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    for ni in instance["NetworkInterfaces"]:
        ec2.modify_network_interface_attribute(NetworkInterfaceId=ni["NetworkInterfaceId"],
                                               Groups=[out["sim_instance_sg_id"]])
    print(f"  {iid}: original security group restored on every ENI")

    assoc = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [iid]}, {"Name": "state", "Values": ["associated"]}]
    )["IamInstanceProfileAssociations"]
    if not assoc:
        ec2.associate_iam_instance_profile(InstanceId=iid, IamInstanceProfile={"Name": out["sim_instance_profile"]})
        print("  instance profile re-associated")

    ec2.modify_instance_attribute(InstanceId=iid, DisableApiTermination={"Value": False})
    ec2.delete_tags(Resources=[iid], Tags=[{"Key": k} for k in ARGUS_TAGS])
    reset_role(session.client("iam"), out["sim_instance_role_name"])
    print("  termination protection off, Argus tags removed")

    account = session.client("sts").get_caller_identity()["Account"]
    release_lock(session, out, f"arn:aws:ec2:{out['region']}:{account}:instance/{iid}")

    if start and instance["State"]["Name"] == "stopped":
        ec2.start_instances(InstanceIds=[iid])
        print("  instance starting")

    if delete_snapshots:
        snaps = ec2.describe_snapshots(OwnerIds=["self"], Filters=[
            {"Name": "tag-key", "Values": ["argus:incident_key"]},
            {"Name": "tag:argus:managed", "Values": ["true"]}])["Snapshots"]
        for s in snaps:
            ec2.delete_snapshot(SnapshotId=s["SnapshotId"])
        print(f"  deleted {len(snaps)} forensic snapshot(s)")


def reset_s3(session, out):
    banner("S3")
    s3 = session.client("s3")
    bucket = out["sim_data_bucket"]
    try:
        s3.delete_bucket_policy(Bucket=bucket)
        print(f"  {bucket}: quarantine policy removed")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDenied":
            print("  AccessDenied removing the quarantine policy: your identity isn't in the exempt list "
                  "(see the quarantine_exempt_principals output). Use an exempt role, or the root user.")
            raise
        raise
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    tags = ignore({"NoSuchTagSet"}, s3.get_bucket_tagging, Bucket=bucket)
    if tags:
        kept = [t for t in tags["TagSet"] if t["Key"] not in ARGUS_TAGS]
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": kept})
    print("  Block Public Access back on, Argus tags removed")
    release_lock(session, out, f"arn:aws:s3:::{bucket}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--iam", action="store_true")
    parser.add_argument("--ec2", action="store_true")
    parser.add_argument("--s3", action="store_true")
    parser.add_argument("--start-instance", action="store_true")
    parser.add_argument("--delete-snapshots", action="store_true")
    args = parser.parse_args()
    if not (args.all or args.iam or args.ec2 or args.s3):
        parser.error("choose --all, --iam, --ec2 and/or --s3")

    out = tf_outputs()
    session = operator_session(out["region"])
    if args.all or args.iam:
        reset_iam(session, out)
    if args.all or args.ec2:
        reset_ec2(session, out, args.start_instance, args.delete_snapshots)
    if args.all or args.s3:
        reset_s3(session, out)
    print("\nDone. Incident records in DynamoDB and evidence in S3 are kept.")


if __name__ == "__main__":
    main()
