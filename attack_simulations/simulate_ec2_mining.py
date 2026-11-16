"""Simulation 2 - EC2 crypto-mining.

Runs DNS lookups of well-known mining-pool domains ON the simulation instance through
SSM Run Command (no SSH). GuardDuty sees them in the VPC's DNS logs.
Nothing is downloaded and no mining software runs.

Expected: CryptoCurrency:EC2/BitcoinTool.B!DNS (HIGH) within ~5-15 min, then the
argus-ec2-playbook execution.

Tip (Phase 5 test): open a Session Manager shell to the instance before the playbook
runs and keep it open - containment should cut it off.
"""

import argparse
import time

from common import banner, operator_session, tf_outputs

POOL_DOMAINS = [
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "pool.supportxmr.com",
    "xmr-eu1.nanopool.org",
    "stratum.slushpool.com",
    "eth.2miners.com",
]


def build_script(rounds: int) -> list[str]:
    domains = " ".join(POOL_DOMAINS)
    return [
        "set +e",
        f"for i in $(seq 1 {rounds}); do",
        f"  for d in {domains}; do getent hosts \"$d\" >/dev/null 2>&1; echo \"lookup $d\"; done",
        "  sleep 10",
        "done",
        "echo 'argus mining simulation finished (DNS lookups only)'",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=12, help="lookup rounds, 10s apart (default 12 = ~2 min)")
    args = parser.parse_args()

    out = tf_outputs()
    ssm = operator_session(out["region"]).client("ssm")
    instance_id = out["sim_instance_id"]

    banner(f"Sending mining-pool DNS lookups to {instance_id}")
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Comment="Argus EC2 mining simulation (DNS lookups only)",
        Parameters={"commands": build_script(args.rounds)},
        TimeoutSeconds=600,
    )["Command"]["CommandId"]
    print(f"SSM command {cmd} sent; waiting for it to finish...")

    while True:
        time.sleep(10)
        inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break
    print(f"Status: {inv['Status']}")
    print((inv.get("StandardOutputContent") or "")[-500:])
    print("\nWatch for the finding, then the argus-ec2-playbook execution.")
    print("Re-running? First: python attack_simulations/reset_simulation.py --ec2")


if __name__ == "__main__":
    main()
