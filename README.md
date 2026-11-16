# Argus — Automated Cloud SOAR on AWS

> Argus Panoptes, the hundred-eyed giant who never slept.

Argus detects three simulated attacks against deliberately weak AWS resources and
responds automatically. Each response preserves forensic evidence first, then
contains, eradicates, packages a SHA-256-hashed evidence bundle under S3 Object
Lock, and notifies a human. Everything is deployed with Terraform.

| Scenario | GuardDuty finding | Playbook |
|---|---|---|
| Leaked IAM access key used from a "malicious" IP | `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` (MEDIUM) | Deactivate keys, attach `AWSDenyAll`, revoke assumed-role sessions, remove console access |
| Instance resolving crypto-mining pools | `CryptoCurrency:EC2/BitcoinTool.B!DNS` (HIGH) | Untrack-then-isolate security group swap per ENI, revoke instance credentials, snapshot, stop |
| Bulk S3 reads from a "malicious" IP | `Discovery:S3/MaliciousIPCaller.Custom` (HIGH) + `Policy:S3/BucketBlockPublicAccessDisabled` (LOW) | Block Public Access on, drop public policy, quarantine policy, versioning, chain into the IAM playbook |

The full design is in [argus_soar_spec.md](argus_soar_spec.md).

## Architecture

```
GuardDuty ─┐
Config ────┴─► Security Hub (ASFF) ─► EventBridge rule (type, severity, NEW/ACTIVE, exact resource)
                                              │ input transformer → envelope
                                              ▼
                          Step Functions (one per playbook, same template)
   Validate → RecordIncident (conditional put) → PreserveEvidence → Contain → Eradicate
            → PackageEvidence → Finalize → Notify → wait 15 min → CollectLateEvidence
   any phase fails → MarkFailed → NotifyFailure (always escalated)
```

## Repository layout

```
lambdas/
  shared/python/argus_shared/   Lambda layer: envelope, phase recorder, AWS helpers
  validator/ forensics/ playbooks/{iam_breach,ec2_mining,s3_exfil}/
  package_evidence/ finalize/ notifier/ late_evidence/
terraform/
  bootstrap/                    state bucket (applied once)
  modules/                      kms, vpc, vpc_flow_logs, quarantine_sg, guardduty, cloudtrail,
                                athena, config, security_hub, evidence_bucket, dynamodb, sns,
                                budget, attack_targets, lambda_roles, lambdas, step_functions,
                                eventbridge (the ASL template lives in modules/step_functions)
attack_simulations/             simulate_*.py, sample_findings.py, reset_simulation.py
tests/unit/                     pytest + moto
tests/events/                   synthetic finding fixtures (replace with real captures)
```

## Prerequisites

- Terraform ≥ 1.10 and Python 3.12
- AWS credentials for your account in the environment (an AWS CLI profile, SSO or
  environment variables) with permission to create everything above
- A VPN or proxy with a fixed public egress IP (for the threat list)

```bash
python -m pip install -r requirements-dev.txt
```

## Running the tests

```bash
python -m pytest
```

The tests use moto, which does **not** enforce IAM. Permissions and KMS key policies
are only proven by the live end-to-end simulations.

## Deploying

1. **Check what your account already has.** Only one GuardDuty detector, one Security
   Hub and one Config recorder can exist per region. If any is already enabled, set
   the matching `create_*`/`enable_*` variable to `false` (see `terraform.tfvars.example`).
2. **Bootstrap the state bucket (once):**
   ```bash
   cd terraform/bootstrap
   terraform init
   terraform apply -var region=us-east-1
   ```
3. **Configure:** copy `terraform/backend.hcl.example` to `backend.hcl` and
   `terraform.tfvars.example` to `terraform.tfvars`, then fill both in.
4. **Deploy:**
   ```bash
   cd terraform
   terraform init -backend-config=backend.hcl
   terraform plan -out argus.tfplan
   terraform apply argus.tfplan
   ```
5. **After apply:** confirm the SNS subscription email, and optionally store the Discord
   webhook in SSM (it is never put in Terraform):
   ```bash
   aws ssm put-parameter --name /argus/notifier/webhook-url --type SecureString --key-id alias/argus-ssm-key --overwrite --value "https://discord.com/api/webhooks/..."
   ```

## Running the simulations

```bash
python attack_simulations/simulate_iam_breach.py
python attack_simulations/simulate_ec2_mining.py
python attack_simulations/simulate_s3_exfil.py
```

Findings take roughly 5–15 minutes to appear. Watch the Step Functions console, the
`argus-incidents` table and the evidence bucket. Reset before re-running a scenario:

```bash
python attack_simulations/reset_simulation.py --all --start-instance
```

**Phase 3 first:** save the first real execution input of each playbook into
`tests/events/` and check the EventBridge patterns (`Types` strings, IAM
`PrincipalName`) against it. The fixtures in the repo are synthetic.

## Verifying evidence

```bash
aws s3 cp s3://<evidence-bucket>/evidence/<incident_key>/final_package.json .
aws s3 cp s3://<evidence-bucket>/evidence/<incident_key>/sha256.txt .
sha256sum -c sha256.txt
```

## Teardown

```bash
python attack_simulations/reset_simulation.py --all --delete-snapshots
cd terraform && terraform destroy
```

- Evidence under Object Lock can't be deleted until retention ends (default:
  GOVERNANCE, 1 day). With COMPLIANCE, the evidence bucket survives `destroy` until then.
- The identity that ran `apply` is automatically exempt from the S3 quarantine
  policy. If you destroy as someone else, remove that policy first (reset script).

## Cost and safety

- The budget alarm is created when `alert_email` is set. After the free trials,
  GuardDuty, Security Hub, Config, CloudTrail data events, three KMS keys and snapshots
  typically come to tens of dollars a month at this scale. Tear down between sessions.
- Attack targets are tagged `argus:managed=true` and named `argus-sim-*`. Routing
  rules, the validator and every remediation permission are limited to them.
- No SSH open to the internet, no mining software, account-level S3 Block Public
  Access untouched (the public-bucket demo needs you to turn it off yourself).
- The simulation access keys are in SSM SecureString but also in Terraform state.
  They belong to throwaway users with read-only access to fake data.

## Differences from the spec

- One ASL template renders all three state machines (the spec lists three files).
- The Validator is shared; the state machine passes the playbook name in the payload.
- Simulations are Python/boto3 instead of a mix of Python and shell, so they run on
  Windows without the AWS CLI. The EC2 lookups run on the instance through SSM Run Command.
- `reset_simulation.py` was added for re-runs and clean teardown.
