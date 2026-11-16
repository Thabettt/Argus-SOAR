# Argus — Automated Cloud SOAR Platform
### Project Specification v1.1

> **v1.1 changes (Nov 2026):** per-rule severity thresholds; idempotency keyed on the Security Hub finding ID; ASFF `Types` matching; atomic conditional-write validator plus failure path; forensic sources that actually return data (Athena for CloudTrail data events, provisioned Flow Logs); corrected IAM/EC2/S3 playbook API calls; complete least-privilege table; Object Lock retention that can be torn down; cost and safety guardrails; Terraform state, packaging and testing.

> Argus Panoptes: the hundred-eyed giant of Greek mythology who never slept.
> Every eye watches. Every threat gets a response.

---

## 0. Project Summary

Argus is a production-grade **Security Orchestration, Automation, and Response (SOAR)** platform built entirely on AWS serverless infrastructure and deployed via Terraform. It simulates three distinct cyberattack vectors against an intentionally vulnerable cloud environment, detects them through AWS-native security services, and executes fully automated, multi-step remediation playbooks — including forensic preservation before containment — without human intervention.

**The distinction from tutorial implementations:** most IR automation projects trigger a single Lambda to "fix" the issue. Argus uses AWS Step Functions to orchestrate multi-step, stateful workflows that mirror how real enterprise security teams operate: preserve evidence first, contain second, eradicate third, notify last.

**Stack:** Terraform · Python 3.12 (Boto3) · AWS GuardDuty · CloudTrail · AWS Config · Security Hub (CSPM, ASFF findings) · EventBridge · Step Functions · Lambda · DynamoDB · Athena · SNS · S3 · KMS · IAM · VPC · EC2

> **Security Hub note:** the ASFF-based findings and "Security Hub Findings - Imported" events used throughout this spec come from the service AWS now calls *Security Hub CSPM*. Confirm this in the console of the region you deploy to before building Phase 3.

---

## 1. Goals & Success Criteria

| Goal | Measurable Outcome |
|---|---|
| Prove IaC mastery | 100% of infrastructure deployed via Terraform with zero manual console steps |
| Prove NIST IR knowledge | Correct phase ordering: Preserve → Contain → Eradicate → Notify |
| Cover SCS exam domains | GuardDuty, CloudTrail, Security Hub, IAM least-privilege, KMS, S3 Object Lock |
| Demonstrate enterprise thinking | Security/app separation with an assume-role remediation pattern (single account, or two accounts if available), severity-based routing, idempotency guards |
| Time to containment | Under 60 seconds from the finding event reaching EventBridge to the contained state (measured as `containment_complete - event_received`). GuardDuty and Security Hub add several minutes between the attack and the finding; report that separately as detection latency |
| Stay within budget | AWS Budget alarm in place from day 1; complete teardown with `terraform destroy` |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK SIMULATION                        │
│         (Terraform-provisioned vulnerable resources)        │
│   [Backdoor IAM User] [Exposed EC2] [Misconfigured S3]      │
└──────────────────────┬──────────────────────────────────────┘
                       │ Malicious activity detected
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  DETECTION LAYER                            │
│   GuardDuty  ──┐                                            │
│   CloudTrail ──┼──► Security Hub (aggregation)             │
│   AWS Config ──┘                                            │
└──────────────────────┬──────────────────────────────────────┘
                       │ Findings published as events
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   ROUTING LAYER                             │
│              Amazon EventBridge                             │
│   Rule per finding type, per-rule severity threshold        │
│   Only NEW + ACTIVE findings → correct Step Functions ARN   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│               ORCHESTRATION LAYER                           │
│              AWS Step Functions                             │
│                                                             │
│  [Validate] → [Preserve Evidence] → [Contain]              │
│       → [Eradicate] → [Package Evidence] → [Notify]        │
└──────┬──────────────┬──────────────┬───────────────────────┘
       │              │              │
       ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────┐
│ Playbook 1 │ │ Playbook 2 │ │ Playbook 3 │
│ IAM Breach │ │ EC2 Mining │ │ S3 Exfil   │
│  (Python)  │ │  (Python)  │ │  (Python)  │
└────────────┘ └────────────┘ └────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 POST-INCIDENT LAYER                         │
│  Evidence Package (S3 + Object Lock)                        │
│  SHA-256 Digest of evidence bundle                          │
│  Discord/Slack Webhook alert                                │
│  SNS Email escalation (CRITICAL only)                       │
│  Automated runbook written to S3                            │
│  Security Hub finding → Workflow.Status = RESOLVED          │
└─────────────────────────────────────────────────────────────┘

Any phase fails ──► Catch ──► MarkFailed (DynamoDB) ──► Failure alert
```

---

## 3. Account Structure

Even if you use a single AWS account, structure your resources as if they are two accounts. Use separate S3 prefixes, IAM boundaries, and resource tags to simulate the separation. If you have AWS Organizations access, use two actual accounts.

**Security Account (or prefix: `security/`)**
- GuardDuty master detector
- CloudTrail organization trail
- Security Hub aggregator
- Evidence S3 bucket (Object Lock enabled)
- Lambda execution roles
- Step Functions state machines
- EventBridge rules

**Application Account (or prefix: `app/`)**
- VPC with public/private subnets
- Vulnerable EC2 instance
- Backdoor IAM user
- Misconfigured S3 bucket
- Quarantine controls (pre-provisioned): `argus-quarantine-isolate`, a security group with no rules (blocks new connections), and `argus-quarantine-nacl`, a network ACL with no rules (cuts existing connections on a dedicated subnet)
- VPC Flow Logs for the VPC, delivered to CloudWatch Logs
- `argus-remediation-role`: the role that playbooks assume to change app resources

**Remediation role pattern (decision: single account by default).** Playbook Lambdas do not hold remediation permissions themselves. Each Lambda execution role can only call `sts:AssumeRole` on `argus-remediation-role` (plus its own logging and evidence writes). The remediation role's trust policy allows only those Lambda roles, and it holds the actual IAM/EC2/S3 write permissions, scoped by resource tag `argus:managed=true`. In a single account this demonstrates the same mechanism as the cross-account pattern (an SCS exam topic). Moving to two real accounts only changes the role ARN's account ID and the trust policy principal.

Keep the README honest: describe this as "single-account deployment, cross-account-ready", not as multi-account.

---

## 4. Terraform Structure

```
argus/
├── terraform/
│   ├── modules/
│   │   ├── vpc/
│   │   │   ├── main.tf          # VPC, subnets, IGW, route tables
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── vpc_flow_logs/
│   │   │   └── main.tf          # Flow logs → CloudWatch Logs group
│   │   ├── kms/
│   │   │   └── main.tf          # cloudtrail, evidence, ssm CMKs + key policies
│   │   ├── guardduty/
│   │   │   ├── main.tf          # Detector, S3 protection, custom threat intel set
│   │   │   └── variables.tf
│   │   ├── cloudtrail/
│   │   │   ├── main.tf          # Trail, log bucket, data event selectors
│   │   │   └── variables.tf
│   │   ├── athena/
│   │   │   └── main.tf          # Glue table over CloudTrail logs, workgroup
│   │   ├── config/
│   │   │   └── main.tf          # Recorder, delivery channel, s3-bucket-public-read-prohibited
│   │   ├── security_hub/
│   │   │   ├── main.tf          # Hub enablement, product integrations
│   │   │   └── variables.tf
│   │   ├── attack_targets/
│   │   │   ├── main.tf          # Vulnerable EC2, backdoor IAM, simulation S3 bucket
│   │   │   └── variables.tf
│   │   ├── quarantine_sg/
│   │   │   ├── main.tf          # isolate security group + deny-all quarantine NACL
│   │   │   └── variables.tf
│   │   ├── evidence_bucket/
│   │   │   ├── main.tf          # S3 + Object Lock (mode/retention via variables) + KMS
│   │   │   └── variables.tf
│   │   ├── dynamodb/
│   │   │   └── main.tf          # argus-incidents table (PK: finding_id)
│   │   ├── sns/
│   │   │   └── main.tf          # CRITICAL escalation topic + email subscription
│   │   ├── lambda_roles/
│   │   │   ├── main.tf          # Per-Lambda execution roles + argus-remediation-role
│   │   │   └── variables.tf
│   │   ├── lambdas/
│   │   │   └── main.tf          # Functions, shared layer, log groups
│   │   ├── step_functions/
│   │   │   ├── main.tf          # State machine definitions
│   │   │   ├── iam_playbook.asl.json
│   │   │   ├── ec2_playbook.asl.json
│   │   │   └── s3_playbook.asl.json
│   │   ├── eventbridge/
│   │   │   ├── main.tf          # Rules, targets, input transformers
│   │   │   └── variables.tf
│   │   └── budget/
│   │       └── main.tf          # AWS Budget + email alert
│   ├── bootstrap/
│   │   └── main.tf              # Remote state bucket (versioned, encrypted); applied once
│   ├── backend.tf               # S3 backend with use_lockfile = true
│   ├── main.tf                  # Composes modules, tagged security/ vs app/
│   ├── variables.tf
│   └── outputs.tf
├── lambdas/
│   ├── shared/                  # Packaged as a Lambda layer
│   │   ├── aws_utils.py
│   │   ├── envelope.py          # Incident envelope schema + validation
│   │   └── constants.py
│   ├── validator/
│   │   └── handler.py
│   ├── forensics/
│   │   └── handler.py
│   ├── playbooks/
│   │   ├── iam_breach/
│   │   │   └── handler.py
│   │   ├── ec2_mining/
│   │   │   └── handler.py
│   │   └── s3_exfil/
│   │       └── handler.py
│   ├── package_evidence/
│   │   └── handler.py
│   ├── finalize/
│   │   └── handler.py           # Marks DynamoDB COMPLETE, resolves Security Hub finding
│   └── notifier/
│       └── handler.py           # Success, CRITICAL escalation and failure alerts
├── tests/
│   ├── unit/                    # pytest + moto per handler
│   └── events/                  # Captured real Security Hub events (fixtures)
├── attack_simulations/
│   ├── simulate_iam_breach.py
│   ├── simulate_ec2_mining.sh
│   ├── simulate_s3_exfil.py
│   └── sample_findings.sh       # guardduty create-sample-findings (routing tests only)
├── docs/
│   ├── architecture.md
│   ├── threat_model.md
│   └── incident_reports/    # Written after each simulated incident
└── README.md
```

---

## 5. Attack Simulations

All simulations target only resources tagged `argus:managed=true` and named `argus-sim-*`. Routing rules match those exact resources (see §7), so Argus never acts on anything else in the account.

**Threat list setup (shared by simulations 1 and 3):** put the egress IP of your VPN or proxy in a GuardDuty custom threat intel set. Calls from that IP produce the `.Custom` variant of the `MaliciousIPCaller` findings. Threat lists only accept public IPs, and a newly activated list can take a few minutes to take effect.

### 5.1 Simulation 1 — IAM Credential Compromise

**What Terraform provisions:**
- An IAM user `argus-sim-backdoor` with programmatic access
- Access key stored as an SSM `SecureString` parameter (simulating a leaked `.env` file)
- IAM policy attached: read-only to a non-sensitive S3 bucket

**What the simulation script does:**
- Makes legitimate-looking API calls (`s3:ListBuckets`, `iam:GetUser`) from your normal IP
- Switches to the VPN/proxy IP on the threat list and calls `iam:CreateUser` and `ec2:DescribeInstances`. These are denied by the user's policy, but CloudTrail still records them, and the source IP is what GuardDuty flags.
- Expected finding: `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` (**MEDIUM** severity)

**Why this finding:** IAM findings are the most heavily weighted in the SCS exam. Credential exfiltration and unauthorized API usage from anomalous IPs are real-world breach vectors.

---

### 5.2 Simulation 2 — EC2 Crypto-Mining

**What Terraform provisions:**
- An EC2 instance (`t3.micro`) in a public subnet, using the VPC's Amazon-provided DNS
- An instance profile with minimal permissions (so the playbook's credential-revocation step has something real to revoke)
- Access through SSM Session Manager. If you need SSH, allow port 22 only from `var.operator_cidr`, never `0.0.0.0/0`: an instance that is genuinely open attracts real attackers within minutes.

**What the simulation script does:**
- Runs repeated DNS lookups (`dig`/`nslookup`) of well-known mining-pool domains from the instance. GuardDuty flags these from DNS logs.
- Does **not** download or run mining software. That isn't needed, and the binary-signature detection would require GuardDuty Runtime Monitoring with its agent.
- Expected finding: `CryptoCurrency:EC2/BitcoinTool.B!DNS` (**HIGH** severity)

**Why this finding:** EC2 runtime threats are a core GuardDuty use case and appear heavily in both SAA and SCS exam scenarios.

---

### 5.3 Simulation 3 — S3 Data Exfiltration / Public Exposure

**What Terraform provisions:**
- An S3 bucket `argus-sim-data-*`, created **private**: bucket-level Block Public Access on, versioning on
- Synthetic "sensitive" files: fake PII CSVs and a fake credentials file (all values clearly fake)
- An IAM user `argus-sim-exfil` with read access to that bucket only
- GuardDuty S3 Protection enabled (required for S3 data-event findings)

**What the simulation script does:**
1. Calls `put_public_access_block` to turn off the bucket's Block Public Access. Expected finding: `Policy:S3/BucketBlockPublicAccessDisabled` (**LOW**).
2. From the threat-list IP, using `argus-sim-exfil`, runs a burst of `ListObjectsV2` and `GetObject` calls (the exfiltration pattern). Expected finding: `Discovery:S3/MaliciousIPCaller.Custom` (**HIGH**).
3. *Optional, for dual detection:* applies a public-read bucket policy. This only succeeds if the **account-level** Block Public Access setting is off. Keep account-level BPA on by default; only turn it off on purpose with `var.allow_public_exposure_demo = true`, and only for the length of the demo. When it succeeds, the AWS Config rule `s3-bucket-public-read-prohibited` also fires.

**Why this finding:** S3 misconfigurations are the most common real-world cloud breach. The two GuardDuty signals (and, optionally, Config) demonstrate defense-in-depth.

---

## 6. Detection Layer

### GuardDuty
- Enable in the deployment region (one region keeps cost and complexity down; document this choice)
- Enable S3 Protection
- Configure the custom threat intel set described in §5
- Findings Argus handles:

| Finding | Severity | Simulation |
|---|---|---|
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | MEDIUM | 5.1 |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | HIGH | 5.2 |
| `Discovery:S3/MaliciousIPCaller.Custom` | HIGH | 5.3 |
| `Policy:S3/BucketBlockPublicAccessDisabled` | LOW | 5.3 (scoped to the simulation bucket only) |

- GuardDuty maps its numeric severity to ASFF labels in Security Hub: 1.0–3.9 LOW, 4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0+ CRITICAL

### CloudTrail
- Enable a multi-region trail
- Log all management events, plus S3 data events for the simulation bucket only (data events are billed per event)
- Store logs in an S3 bucket encrypted with a customer-managed KMS key
- Enable log file validation (SHA-256 digest files). This is an SCS exam topic and ties to your cryptographic background.
- Create an Athena table over the trail bucket. `cloudtrail:LookupEvents` returns **management events only**, delivered 5–15 minutes late and rate-limited to about 2 requests/second. S3 data events can only be queried through Athena (or CloudTrail Lake).

### VPC Flow Logs
- Enable for the VPC, delivered to a CloudWatch Logs group (KMS-encrypted, 30-day retention)
- Records arrive with up to about 10 minutes' delay, so flow-log evidence is collected later (see §8, `CollectLateEvidence`), not in the containment path

### AWS Config
- Enable the recorder for the simulation resource types (S3 buckets, EC2, security groups, IAM users) rather than all resources, to keep cost down
- Add the managed rule `s3-bucket-public-read-prohibited`
- It fires independently of GuardDuty in the optional public-exposure step of the S3 scenario

### Security Hub
- Enable it and integrate GuardDuty and Config as finding sources (CloudTrail is not a finding source; Security Hub controls evaluate it through Config)
- Security Hub normalizes findings into ASFF (AWS Security Finding Format)
- EventBridge listens to Security Hub rather than to GuardDuty directly. This is the enterprise pattern, because Security Hub aggregates findings from many services. The cost is a little extra latency, which counts as detection latency, not containment time.

---

## 7. Routing Layer — EventBridge

Create one EventBridge rule per playbook. Each rule:
1. Matches `source = aws.securityhub` and `detail-type = Security Hub Findings - Imported`
2. Matches GuardDuty findings by the ASFF **`Types`** array. ASFF has no `Type` field; GuardDuty types appear as namespaced strings with `/` replaced by `-`, for example `TTPs/Initial Access/UnauthorizedAccess:IAMUser-MaliciousIPCaller.Custom`. Use `wildcard` matching.
3. Applies its **own** severity threshold (table below). There is no global HIGH/CRITICAL filter.
4. Matches only `Workflow.Status = NEW` and `RecordState = ACTIVE`. Security Hub re-sends "Imported" events every time a finding is updated, including when Argus resolves it, and this filter drops those repeats.
5. Is scoped to the Argus simulation resources (resource ARNs and names come from Terraform outputs)
6. Targets the playbook's Step Functions state machine, through an input transformer

EventBridge patterns cannot index arrays (`findings[0]` is not valid in a pattern); a field pattern matches if any element matches. Security Hub sends one finding per event in practice, and the Validator re-checks `findings[0]`.

| Rule | `Types` wildcard | Min severity | Scope |
|---|---|---|---|
| `argus-iam` | `*UnauthorizedAccess:IAMUser-MaliciousIPCaller*` | MEDIUM | IAM principal name starts with `argus-sim-` |
| `argus-ec2` | `*CryptoCurrency:EC2-BitcoinTool*` | HIGH | `Resources.Id` = the simulation instance ARN |
| `argus-s3` | `*Discovery:S3-MaliciousIPCaller*` | HIGH | `Resources.Id` = the simulation bucket ARN |
| `argus-s3-policy` | `*Policy:S3-BucketBlockPublicAccessDisabled*` | LOW | `Resources.Id` = the simulation bucket ARN (allowed below HIGH only because it is limited to that bucket) |
| `argus-s3-config` *(v1.2)* | ProductName `Config`, Title `argus-s3-bucket-public-read-prohibited`, Compliance `FAILED` | any | the simulation bucket ARN. Config flags a public bucket in under a few minutes; GuardDuty's update took ~10 min. Measured: exposure 618 s → 218 s |

**Pattern example (EC2):**
```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "ProductName": ["GuardDuty"],
      "Types": [{ "wildcard": "*CryptoCurrency:EC2-BitcoinTool*" }],
      "Severity": { "Label": ["HIGH", "CRITICAL"] },
      "Workflow": { "Status": ["NEW"] },
      "RecordState": ["ACTIVE"],
      "Resources": { "Id": ["arn:aws:ec2:REGION:ACCOUNT:instance/i-SIMULATION"] }
    }
  }
}
```

> **Verify field paths with real events.** The `Types` strings and the IAM principal field (expected at `Resources[].Details.AwsIamAccessKey.PrincipalName`) are best confirmed against a captured event. Phase 3 saves real events to `tests/events/`, and the patterns are tuned against those.

**Input transformer** (input paths map plus template):
```json
{
  "InputPathsMap": {
    "event_id": "$.id",
    "event_received": "$.time",
    "finding_id": "$.detail.findings[0].Id",
    "product_arn": "$.detail.findings[0].ProductArn",
    "finding_type": "$.detail.findings[0].Types[0]",
    "severity": "$.detail.findings[0].Severity.Label",
    "finding_created": "$.detail.findings[0].CreatedAt",
    "account": "$.detail.findings[0].AwsAccountId",
    "region": "$.detail.findings[0].Region",
    "resource": "$.detail.findings[0].Resources[0]"
  },
  "InputTemplate": "{\"incident_id\": <finding_id>, \"finding_id\": <finding_id>, \"product_arn\": <product_arn>, \"event_id\": <event_id>, \"event_received\": <event_received>, \"finding_type\": <finding_type>, \"severity\": <severity>, \"finding_created\": <finding_created>, \"account\": <account>, \"region\": <region>, \"resource\": <resource>}"
}
```

**`incident_id` is the Security Hub finding ID, not the EventBridge event ID.** Every event has a new event ID, so keying on it would make the idempotency guard useless. The finding ID stays the same across every re-delivery and update of the same finding. Use a hash of it wherever a shorter, S3-safe key is needed (`incident_key = sha256(finding_id)[:16]`).

The Validator turns this input into the **incident envelope** (`shared/envelope.py`): the fields above plus a normalized `target` (`{ "kind": "iam_user" | "ec2_instance" | "s3_bucket", "id": ..., "arn": ... }`). Every later Lambda receives this same envelope. Design the Lambdas around this contract.

---

## 8. Orchestration Layer — Step Functions

Each playbook has its own state machine. All three share the same phase structure and the same Validator, Forensics, PackageEvidence, Finalize and Notifier Lambdas (the Forensics Lambda branches on `target.kind`). They are defined in Amazon States Language (ASL).

### State Machine Phase Sequence

```
ValidateFinding            (Lambda: build envelope, check scope)
     │
RecordIncident             (direct DynamoDB PutItem, conditional)
     ├── ConditionalCheckFailed ──► AlreadyHandled (Succeed)   ← idempotency guard
     ▼
PreserveEvidence
     ▼
Contain
     ▼
Eradicate
     ▼
PackageEvidence
     ▼
Finalize                   (DynamoDB → COMPLETE, Security Hub → RESOLVED)
     ▼
Notify
     ▼
CollectLateEvidence        (Wait 15 min → Athena / Flow Logs query → supplemental evidence)
     ▼
End

Any state from PreserveEvidence to Notify:
  Catch States.ALL ──► MarkFailed (DynamoDB → FAILED + error) ──► NotifyFailure ──► Fail
```

**Error handling rules:**
- Every Lambda task has `Retry` on `Lambda.ServiceException`, `Lambda.TooManyRequestsException`, `Lambda.SdkClientException` and throttling errors (exponential backoff, at most 3 attempts)
- Every task has its own `TimeoutSeconds`. Task timeouts raise `States.Timeout`, which `Catch` can handle. Do not rely on a state-machine-level timeout: no Catch runs when the whole execution times out, and the incident would stay `IN_PROGRESS`.
- Retries mean any task can run more than once, so **every Lambda must be idempotent by itself**. Deactivating a key that is already inactive is fine. Before creating an EBS snapshot, check whether one tagged `argus:incident_key=<key>` already exists.

**State data contract:** each phase writes its result to its own path (`ResultPath`): `$.evidence`, `$.containment`, `$.eradication`, `$.package`. Each phase result has this shape:
```json
{ "started_at": "ISO-8601", "completed_at": "ISO-8601",
  "actions": [ { "action": "iam:UpdateAccessKey", "target": "AKIA…", "result": "ok", "at": "ISO-8601" } ] }
```
`time_to_contain_seconds = $.containment.completed_at − event_received`.

### Why Step Functions over a single Lambda

- Each phase is a separate Lambda invocation. If containment succeeds but notification fails, Step Functions retries *only* the notification; it does not re-contain.
- The execution history is logged automatically with timestamps, giving a full audit trail per incident
- Wait states, parallel branches and error handling (`Catch`) live at the workflow level
- Direct service integrations (DynamoDB here) remove Lambdas that would only wrap a single API call
- The visual execution graph in the AWS console is a legitimate artifact to screenshot for your GitHub README

---

## 9. Lambda Playbooks

### 9.1 Shared Layer (`lambdas/shared/`)

```python
# envelope.py
# - build_envelope(transformer_input) → Envelope   (validates, normalizes target)
# aws_utils.py
# - assume_role(role_arn, session_name) → boto3.Session   (remediation / forensics roles)
# - get_ssm_parameter(name, decrypt=True) → value
# - put_evidence(incident_key, name, data) → s3 URI   (SSE-KMS with the evidence key)
# - tag_resource(target, tags) → None
# - lookup_management_events(username|resource_name, start, end) → [events]   (LookupEvents, paginated, throttle-aware)
# - start_athena_query(sql) → query_execution_id
# - record_action(phase_result, action, target, result) → None
```

Packaged as a Lambda layer so every function uses the same envelope and helpers.

---

### 9.2 ValidateFinding Lambda + RecordIncident

**ValidateFinding (Lambda):**
1. Build the incident envelope from the transformer input
2. Reject anything out of scope: the target must be named `argus-sim-*` (IAM, S3) or match the configured simulation instance ID (EC2). Out of scope → `Fail` with a clear error. This repeats the EventBridge scoping as defense in depth.

**RecordIncident (direct DynamoDB integration, no Lambda):**
- `PutItem` on table `argus-incidents` (partition key `finding_id`) with `status = IN_PROGRESS` and `started_at`
- `ConditionExpression: attribute_not_exists(finding_id) OR #status = :failed`
- The check and the write are **one atomic call**. With a separate "check, then write", two executions started at the same moment could both see "not found" and both remediate.
- `ConditionalCheckFailedException` → `AlreadyHandled` (Succeed state)
- A previously `FAILED` incident can run again. This is safe because every phase is idempotent.

**Why this matters:** without idempotency, a finding delivered twice would start two simultaneous remediations on the same resource. That's a real production problem.

---

### 9.3 PreserveEvidence Lambda (ForensicsCollector)

**Purpose:** capture the forensic state of the environment *before* anything is changed. This is the step most tutorials skip. Evidence preservation is part of the containment, eradication and recovery phase of NIST SP 800-61.

Runs as `argus-forensics-role` (read-only, plus snapshot creation). Everything is written under `evidence/{incident_key}/pre_containment.json`.

**For IAM incidents:**
- `iam:GetUser`, `iam:ListGroupsForUser`, `iam:GetLoginProfile` — user metadata and console access
- `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` + `iam:GetUserPolicy` — all permissions
- `iam:ListAccessKeys` + `iam:GetAccessKeyLastUsed` — key IDs, status, last use
- `cloudtrail:LookupEvents` (attribute `Username`) for the last hour. Management events only, and the most recent minutes may not be delivered yet; the late-evidence step fills that gap.
- From those events, the roles this user assumed (`AssumeRole`) → returned as `$.evidence.assumed_roles` for the playbook

**For EC2 incidents:**
- `ec2:DescribeInstances` — instance metadata, security groups for each network interface, VPC placement
- `ec2:DescribeIamInstanceProfileAssociations` — the attached instance profile
- `ec2:CreateSnapshot` on every attached EBS volume, tagged `argus:incident_key`. Snapshots complete asynchronously, so record the IDs and don't wait.
- Volatile memory is **not** captured (documented limitation; stopping the instance later erases it)

**For S3 incidents:**
- `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketOwnershipControls`, `s3:GetBucketVersioning`
- `s3:ListObjectVersions` (IAM action `s3:ListBucketVersions`) — every object version that existed during the exposure window

**CollectLateEvidence** (after Notify, outside the containment path):
- Waits 15 minutes for CloudTrail and Flow Logs delivery
- IAM: repeats `LookupEvents` for the full window
- EC2: CloudWatch Logs Insights query of the Flow Logs group for the instance's network interfaces
- S3: Athena query of CloudTrail data events for the bucket (every `GetObject` and `ListObjects` call, with source IP)
- Writes `evidence/{incident_key}/supplemental.json` and its own `supplemental.sha256`

---

### 9.4 Playbook 1 — IAM Breach (`playbooks/iam_breach/handler.py`)

Runs as `argus-remediation-role`.

**Phase: Contain**
1. `iam:ListAccessKeys`, then `iam:UpdateAccessKey(Status=Inactive)` for every key
2. `iam:AttachUserPolicy` with the AWS-managed **`arn:aws:iam::aws:policy/AWSDenyAll`**. This explicit deny applies immediately to requests signed with the user's long-term keys **and** to temporary credentials the user obtained via `GetSessionToken` or `GetFederationToken`, because those are still evaluated against the user's policies.
3. Sessions from **roles** the user assumed are *not* affected by the user's policies. For each role in `$.evidence.assumed_roles` that is tagged `argus:managed=true`, call `iam:PutRolePolicy` with a deny-all inline policy conditioned on `"DateLessThan": { "aws:TokenIssueTime": "<now>" }`. This is the same mechanism as the console's "Revoke active sessions". (The simulation user can't assume roles, so this branch is covered by unit tests rather than the live simulation.)

There is no API that lists a user's active sessions, and `sts:GetCallerIdentity` only returns the caller's own identity, so neither is used.

**Phase: Eradicate** (removes every remaining access path)
1. `iam:DeleteLoginProfile` — disable console access (`NoSuchEntity` counts as success)
2. Tag the user: `argus:status=QUARANTINED`, `argus:incident_key={key}`, `argus:quarantine_time={timestamp}`
3. Access keys are deactivated but **not deleted**: they are evidence. Deleting them is a step in the runbook, after review.

---

### 9.5 Playbook 2 — EC2 Crypto-Mining (`playbooks/ec2_mining/handler.py`)

Runs as `argus-remediation-role`.

**Phase: Contain**
1. Take the original security groups for each network interface from `$.evidence` (already saved, so recovery is possible)
2. For **each** network interface: `ec2:ModifyNetworkInterfaceAttribute(Groups=[argus-quarantine-isolate])`. This blocks every *new* connection. Doing it per network interface also covers instances with more than one (`ModifyInstanceAttribute(Groups=…)` only changes the primary one).
   - **Security groups do not end existing connections.** They are stateful: a flow that was tracked when it started stays allowed whatever the rules become. *(v1.2, verified live: a Session Manager session survived a direct swap to the empty group, and also the widely cited "swap to an allow-all group first to untrack, then isolate" sequence, even with 30 s of traffic in between. The untrack step was removed; it also briefly allowed all traffic.)*
3. If the instance's subnet is tagged `argus:dedicated-subnet=true`: `ec2:ReplaceNetworkAclAssociation` to the deny-all `argus-quarantine-nacl`. NACLs are stateless, so this **cuts live connections within about 2 seconds** (verified live). It affects the whole subnet, hence the opt-in tag. On shared subnets it is skipped, and the stop in Eradicate ends live connections instead. Forensics records the original NACL for recovery.
4. `ec2:DisassociateIamInstanceProfile` (association ID taken from evidence), and add the same `aws:TokenIssueTime` revoke-older-sessions deny to the instance role. Credentials stolen from instance metadata stay valid for hours otherwise.
5. `ec2:ModifyInstanceAttribute(DisableApiTermination=true)` — protect the evidence from deletion
6. Tag the instance: `argus:status=QUARANTINED`, `argus:incident_key={key}`

**Phase: Eradicate**
1. `ec2:StopInstances` — stop, don't terminate. Trade-off: memory is lost, the disk is kept (and already snapshotted).

**Recovery note (document in README):** an operator reviews the evidence, removes the quarantine tag and the revoke-sessions policy, restores the original security groups and instance profile, and rebuilds from a clean AMI (or starts from the snapshot only after analysis if the OS was compromised).

---

### 9.6 Playbook 3 — S3 Exfiltration (`playbooks/s3_exfil/handler.py`)

Runs as `argus-remediation-role`.

**Phase: Contain**
1. `s3:PutBucketPublicAccessBlock` with all four flags set to `true`
2. `s3:DeleteBucketPolicy` — remove the public policy (the original is already in evidence)
3. If `GetBucketOwnershipControls` shows ACLs are enabled (anything other than `BucketOwnerEnforced`): `s3:PutBucketAcl(ACL='private')`. With ACLs disabled, skip this step: ACLs can't grant access in that case.

**Phase: Eradicate**
1. Apply a quarantine bucket policy that denies every principal except the remediation, auditor and Terraform deployer roles. Without the deployer role in the list, `terraform destroy` can't remove the bucket afterwards.
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Sid": "ArgusQuarantine",
       "Effect": "Deny",
       "Principal": "*",
       "Action": "s3:*",
       "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
       "Condition": {
         "ArnNotLike": {
           "aws:PrincipalArn": [
             "arn:aws:iam::ACCOUNT:role/argus-remediation-role",
             "arn:aws:iam::ACCOUNT:role/argus-auditor-role",
             "arn:aws:iam::ACCOUNT:role/TERRAFORM_DEPLOYER_ROLE"
           ]
         }
       }
     }]
   }
   ```
   (The account root user can always remove a bucket policy; that is the break-glass path.)
2. Make sure versioning is on (`s3:PutBucketVersioning`), so no object can be silently overwritten or deleted while under investigation
3. Tag the bucket: `argus:status=QUARANTINED`, `argus:incident_key={key}`
4. *Optional chaining:* if the finding names a calling IAM user that starts with `argus-sim-` (for example `argus-sim-exfil`), start the IAM state machine for that user (`states:StartExecution`), so the stolen credential is contained too

Object Lock is **not** applied to the simulation bucket. Default retention only protects *new* objects, and a Compliance-mode bucket can't be deleted until retention runs out. Object Lock is used only on the evidence bucket.

---

### 9.7 PackageEvidence Lambda

**Purpose:** combine all pre- and post-containment records, compute an integrity hash, and store the result in the evidence bucket.

**Evidence layout** (one prefix per incident):
```
evidence/{incident_key}/pre_containment.json
evidence/{incident_key}/final_package.json
evidence/{incident_key}/sha256.txt
evidence/{incident_key}/supplemental.json        (written later by CollectLateEvidence)
evidence/{incident_key}/supplemental.sha256
runbooks/{incident_key}.md
```

**Logic:**
1. Read `pre_containment.json` and the phase results from the state data (`$.containment`, `$.eradication`)
2. Build the bundle:
   ```json
   {
     "incident_id": "<Security Hub finding ID>",
     "incident_key": "...",
     "finding_type": "...",
     "severity": "...",
     "target": { "kind": "...", "id": "...", "arn": "..." },
     "pre_containment": { ... },
     "remediation_actions": [ ... ],
     "timestamps": {
       "finding_created": "...",
       "event_received": "...",
       "containment_start": "...",
       "containment_complete": "...",
       "detection_latency_seconds": 0,
       "time_to_contain_seconds": 0
     }
   }
   ```
3. Serialize it **canonically** (`json.dumps(bundle, sort_keys=True, separators=(",", ":"))`) so anyone can recompute the same digest from the stored file
4. Compute the SHA-256 digest of those exact bytes
5. Write `final_package.json` and `sha256.txt`
6. The evidence bucket's default Object Lock retention protects both objects (mode and duration come from variables, see §12)

**The SHA-256 step** ties directly to your Aegis background (BLAKE3 for file integrity). Mention this explicitly in your README: you're applying the same principle (tamper-evident evidence) at the cloud infrastructure layer. CloudTrail's own log file validation complements it.

---

### 9.8 Finalize Lambda

1. `dynamodb:UpdateItem` → `status = COMPLETE`, `completed_at`, evidence URI, digest
2. `securityhub:BatchUpdateFindings` (finding ID + product ARN from the envelope) → `Workflow.Status = RESOLVED` with a note: `Contained by Argus — incident {incident_key}`. The "Imported" event this update produces is ignored by the `Workflow.Status = NEW` filter.

---

### 9.9 Notifier Lambda

The webhook URL is stored as an SSM `SecureString` (encrypted with the SSM key), never in code or in a Terraform variable file.

**Discord/Slack webhook payload:**
```json
{
  "embeds": [{
    "title": "🚨 Argus Incident Response — [SEVERITY]",
    "color": 16711680,
    "fields": [
      { "name": "Incident", "value": "...", "inline": true },
      { "name": "Finding Type", "value": "...", "inline": true },
      { "name": "Affected Resource", "value": "...", "inline": false },
      { "name": "Actions Taken", "value": "...", "inline": false },
      { "name": "Time to Containment", "value": "42 seconds", "inline": true },
      { "name": "Evidence Package", "value": "s3://argus-evidence-…/evidence/…/final_package.json", "inline": false }
    ],
    "timestamp": "..."
  }]
}
```

**Escalation:** if severity is at or above `var.escalation_min_severity`, also publish to an SNS topic with an email subscription. The default is `CRITICAL`. None of the three simulations produce a CRITICAL finding, so set it to `HIGH` to demonstrate the escalation path.

**Failure mode:** `NotifyFailure` uses the same Lambda with a red "Remediation FAILED — manual action required" message that includes the failing state and error. Failures are always escalated to SNS.

**Automated Runbook:** write a markdown runbook to `runbooks/{incident_key}.md` after each incident:
```markdown
# Incident Runbook — {incident_key}
**Date:** ...  **Severity:** ...  **Type:** ...
## Timeline
- HH:MM:SS — Finding created by GuardDuty
- HH:MM:SS — Received by EventBridge
- HH:MM:SS — Evidence preserved
- HH:MM:SS — Containment executed
- HH:MM:SS — Eradication complete
## Actions Taken
...
## Evidence Location
s3://argus-evidence-…/evidence/{incident_key}/final_package.json
## SHA-256 Digest
...
## Recovery Steps
...
```

---

## 10. IAM Design — Least Privilege

Each Lambda has its own execution role. No role has more permissions than its single task needs. Remediation and forensics permissions live on the two app-side roles, which only the matching Lambda roles can assume. This is an SCS exam core principle and should be demonstrated explicitly.

**Lambda execution roles**

| Lambda | Permissions granted |
|---|---|
| Validator | none beyond logging (pure function) |
| ForensicsCollector | `sts:AssumeRole` → `argus-forensics-role`; `s3:PutObject` (evidence bucket, `evidence/*`); `kms:GenerateDataKey` (evidence key) |
| CollectLateEvidence | `sts:AssumeRole` → `argus-forensics-role`; `athena:StartQueryExecution`, `athena:GetQueryExecution`, `athena:GetQueryResults` (Argus workgroup); `glue:GetTable`, `glue:GetDatabase`; `s3:GetObject`/`s3:ListBucket` (CloudTrail bucket); `s3:PutObject`/`s3:GetObject` (Athena results prefix); `kms:Decrypt` (CloudTrail key); `logs:StartQuery`, `logs:GetQueryResults` (Flow Logs group); `s3:PutObject` + `kms:GenerateDataKey` (evidence) |
| IAMBreachPlaybook | `sts:AssumeRole` → `argus-remediation-role` |
| EC2MiningPlaybook | `sts:AssumeRole` → `argus-remediation-role` |
| S3ExfilPlaybook | `sts:AssumeRole` → `argus-remediation-role`; `states:StartExecution` (IAM state machine, optional chaining) |
| PackageEvidence | `s3:GetObject`, `s3:PutObject` (evidence bucket); `kms:GenerateDataKey`, `kms:Decrypt` (evidence key) |
| Finalize | `dynamodb:UpdateItem` (incidents table); `securityhub:BatchUpdateFindings` |
| Notifier | `ssm:GetParameter` (webhook parameter); `kms:Decrypt` (SSM key); `sns:Publish` (escalation topic); `s3:PutObject` (`runbooks/*`) + `kms:GenerateDataKey` (evidence key) |

**Step Functions execution role:** `lambda:InvokeFunction` (Argus functions only); `dynamodb:PutItem`, `dynamodb:UpdateItem` (incidents table); CloudWatch Logs delivery for execution logging.

**App-side roles** (trust policies allow only the Lambda roles listed above)

| Role | Permissions granted |
|---|---|
| `argus-forensics-role` | `iam:GetUser`, `iam:GetUserPolicy`, `iam:GetLoginProfile`, `iam:GetAccessKeyLastUsed`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListAccessKeys`, `iam:ListGroupsForUser`; `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `ec2:DescribeIamInstanceProfileAssociations`, `ec2:CreateSnapshot`, `ec2:CreateTags` (snapshots only, on create); `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketOwnershipControls`, `s3:GetBucketVersioning`, `s3:ListBucketVersions` (`argus-sim-*` buckets); `cloudtrail:LookupEvents` |
| `argus-remediation-role` | IAM: `iam:ListAccessKeys`, `iam:UpdateAccessKey`, `iam:AttachUserPolicy` (only for policy ARN `AWSDenyAll`, via `iam:PolicyARN` condition), `iam:DeleteLoginProfile`, `iam:TagUser`, `iam:PutRolePolicy` — all limited to principals tagged `argus:managed=true` (`iam:ResourceTag`). EC2: `ec2:ModifyNetworkInterfaceAttribute`, `ec2:ModifyInstanceAttribute`, `ec2:DisassociateIamInstanceProfile`, `ec2:StopInstances`, `ec2:CreateTags` — limited to resources tagged `argus:managed=true` (`aws:ResourceTag`). S3: `s3:PutBucketPublicAccessBlock`, `s3:DeleteBucketPolicy`, `s3:PutBucketAcl`, `s3:PutBucketPolicy`, `s3:PutBucketVersioning`, `s3:PutBucketTagging`, `s3:GetBucketOwnershipControls` — limited to `arn:aws:s3:::argus-sim-*` |

All Lambda roles also have `logs:CreateLogStream` and `logs:PutLogEvents` on their own log group. Terraform creates the log groups (with retention), so `logs:CreateLogGroup` isn't needed.

Several IAM action names differ from the API call names, for example `PutPublicAccessBlock` → `s3:PutBucketPublicAccessBlock` and `ListObjectVersions` → `s3:ListBucketVersions`. Unit tests can't catch a wrong action name; only the live end-to-end tests do.

---

## 11. KMS Encryption Strategy

- **CloudTrail logs:** encrypted with a customer-managed key (`argus-cloudtrail-key`). The key policy allows the CloudTrail service principal, restricted with `aws:SourceArn` to the Argus trail, and `kms:Decrypt` for CollectLateEvidence.
- **Evidence S3 bucket:** encrypted with a separate key (`argus-evidence-key`). The key policy allows `kms:GenerateDataKey` for the roles that write evidence and `kms:Decrypt` for PackageEvidence and the auditor role.
- **SSM parameters** (simulation credentials, webhook URL): `SecureString`, encrypted with a third key (`argus-ssm-key`), decryptable only by the Notifier and the simulation operator
- **Flow Logs log group:** encrypted with the evidence key
- All keys: automatic rotation on, resource-based key policies following least privilege (about $1 per key per month)

This is directly tested on SCS. One key per data classification boundary.

---

## 12. Cost, Safety & Teardown

**Budget:** create an AWS Budget with an email alert (for example $20/month) in Phase 1, before enabling any paid service. After their free trials end, GuardDuty, Security Hub, Config, CloudTrail data events, three KMS keys and EBS snapshots together cost roughly low tens of dollars per month at this scale. Keep Config recording limited to the simulation resource types and S3 data events limited to the simulation bucket.

**Object Lock on the evidence bucket:** mode and retention come from variables.

| Variable | Dev default | Portfolio demo |
|---|---|---|
| `evidence_lock_mode` | `GOVERNANCE` | `COMPLIANCE` |
| `evidence_lock_days` | `1` | `365` |

In Compliance mode **nobody, including the root user, can delete the objects before retention ends**, so `terraform destroy` fails for the whole retention period and the storage keeps costing money. Use Compliance only for a final demo you accept keeping, and record the choice in the README. Governance mode demonstrates the same feature and can be overridden with `s3:BypassGovernanceRetention`.

**Safety rules:**
- Simulation resources are tagged `argus:managed=true`, named `argus-sim-*`, and every remediation permission is scoped to them
- No SSH open to `0.0.0.0/0`; Session Manager is the default
- No mining software is downloaded or run; the EC2 simulation uses DNS lookups only
- Account-level S3 Block Public Access stays on, except during the optional, flagged public-exposure demo
- Run the simulations, capture the evidence, then tear down. Don't leave the vulnerable targets running between sessions.

**Testing strategy:**
- Unit tests: `pytest` + `moto` for every handler, using captured real events from `tests/events/` as fixtures
- Routing tests: `aws guardduty create-sample-findings` checks EventBridge matching. Sample findings point at fake resources (and won't match the scoped rules unless a temporary test rule is used), so use them for routing only, not for end-to-end playbook runs.
- End-to-end: the three real simulations

**Teardown:** `terraform destroy` removes everything except the evidence objects still under Object Lock retention, and EBS snapshots created at runtime (Terraform doesn't track those; delete by the `argus:incident_key` tag). Disable GuardDuty, Security Hub and Config if you destroy outside Terraform.

---

## 13. Build Sequence

Work in this order. Each phase produces something testable before you move on.

**Phase 0 — Guardrails (Day 1)**
- [ ] AWS Budget with an email alert
- [ ] Terraform `bootstrap/`: remote-state S3 bucket (versioned, encrypted); `backend.tf` with `use_lockfile = true`
- [ ] Pick the deployment region; set default tags (`project=argus`, `argus:managed=true` on simulation resources)

**Phase 1 — Foundation (Days 1–5)**
- [ ] Terraform: KMS keys (CloudTrail, evidence, SSM). CloudTrail needs its key from the start.
- [ ] Terraform: VPC, subnets, IGW, route tables, VPC Flow Logs
- [ ] Terraform: enable GuardDuty (with S3 Protection), CloudTrail (with log file validation and S3 data-event selector), Config (limited recorder + rule), Security Hub
- [ ] Terraform: evidence bucket with Object Lock (`GOVERNANCE`, 1 day) + KMS
- [ ] Terraform: quarantine security group (isolate) and deny-all quarantine NACL
- [ ] Terraform: Athena table over the CloudTrail bucket
- [ ] Verify: CloudTrail is logging and digest files appear; GuardDuty is active; GuardDuty findings appear in Security Hub (generate one sample finding to check)

**Phase 2 — Attack Targets (Days 6–8)**
- [ ] Terraform: simulation EC2 instance (`t3.micro`, Session Manager, minimal instance profile)
- [ ] Terraform: `argus-sim-backdoor` user + access key in SSM
- [ ] Terraform: `argus-sim-data-*` bucket (private, versioned, fake data) + `argus-sim-exfil` user
- [ ] Terraform: GuardDuty custom threat list with your VPN/proxy egress IP
- [ ] Verify: resources exist and are tagged; no unexpected findings at rest

**Phase 3 — Routing (Days 9–11)**
- [ ] EventBridge rules for all four patterns, with a stub target (a Lambda that logs its input)
- [ ] Run simulation 1. Save the raw Security Hub event to `tests/events/` and confirm the `Types` string and the IAM principal field path.
- [ ] Tune the patterns and input transformer against the saved events until the envelope is right
- [ ] Use `create-sample-findings` with a temporary unscoped rule to check matching for the EC2/S3 types, then delete that rule
- [ ] Confirm a resolved or updated finding does **not** trigger the rule again

**Phase 4 — IAM Playbook (Days 12–16)**
- [ ] Shared layer (`envelope.py`, `aws_utils.py`) with unit tests
- [ ] DynamoDB table + RecordIncident (conditional write) + Validator
- [ ] `argus-forensics-role` and `argus-remediation-role` (IAM permissions)
- [ ] ForensicsCollector (IAM branch)
- [ ] IAMBreachPlaybook
- [ ] PackageEvidence (canonical JSON + SHA-256 from the start)
- [ ] Finalize (DynamoDB COMPLETE + Security Hub RESOLVED)
- [ ] Notifier (Discord webhook from SSM) + failure path (Catch → MarkFailed → NotifyFailure)
- [ ] Wire the IAM state machine
- [ ] End-to-end: run simulation 1 and watch the whole flow complete. Then send the same event again and confirm `AlreadyHandled`.
- [ ] Failure test: temporarily remove one permission and confirm the incident ends `FAILED` with an alert

**Phase 5 — EC2 Playbook (Days 17–21)**
- [ ] ForensicsCollector — EC2 branch (EBS snapshot, instance profile association)
- [ ] EC2MiningPlaybook (two-step security-group swap per network interface, credential revocation)
- [ ] EC2 state machine
- [ ] End-to-end: run simulation 2 **with an open Session Manager shell**, and confirm the shell is cut off by containment

**Phase 6 — S3 Playbook (Days 22–26)**
- [ ] ForensicsCollector — S3 branch
- [ ] S3ExfilPlaybook (+ optional chaining into the IAM state machine)
- [ ] S3 state machines (both S3 rules can target the same one)
- [ ] End-to-end: run simulation 3; confirm `terraform plan` still works after the quarantine policy is applied

**Phase 7 — Hardening & Documentation (Days 27–35)**
- [ ] CollectLateEvidence (Athena data events, Flow Logs query, LookupEvents)
- [ ] Review every role against the least-privilege tables; remove anything unused
- [ ] SNS escalation (`escalation_min_severity = HIGH` for the demo)
- [ ] Automated runbook generation
- [ ] Write the threat model (`docs/threat_model.md`), including what Argus does *not* handle (memory forensics, multi-region, real multi-account)
- [ ] Write one incident report per simulation (`docs/incident_reports/`), with measured detection latency and time to containment
- [ ] Architecture diagram (draw.io or Excalidraw, exported to PNG)
- [ ] README: overview, diagram, setup, teardown, cost notes, demo GIFs
- [ ] Final `terraform destroy` test on a clean deploy

---

## 14. Resume Bullets (Final Form)

Only claim what you measured. Fill in the real numbers from your incident reports.

```
Argus — Cloud SOAR Platform | Terraform, AWS GuardDuty, Step Functions, Lambda, Python

• Built an automated incident-response platform on AWS using Step Functions to
  orchestrate multi-phase playbooks (forensic preservation → containment →
  eradication), containing three distinct attack vectors in under N seconds
  from finding receipt.

• Deployed 100% of infrastructure via reusable Terraform modules spanning VPC,
  GuardDuty, CloudTrail, Config, Security Hub, and KMS-encrypted evidence
  storage with S3 Object Lock for tamper-evident chain of custody.

• Engineered Python/Boto3 playbooks that isolate compromised EC2 instances
  (cutting live sessions with a stateless NACL), revoke IAM credentials and sessions via explicit
  deny policies, and remediate S3 public exposure, run through a scoped
  remediation role and gated by an atomic DynamoDB idempotency check.

• Implemented a cryptographic evidence pipeline computing SHA-256 digests over
  canonical forensic bundles (IAM snapshots, CloudTrail events, EBS snapshot
  references) and preserving them under S3 Object Lock, following
  NIST SP 800-61 evidence-handling guidance.
```

---

## 15. SCS Exam Coverage

| SCS Domain | Argus Feature |
|---|---|
| Threat Detection (GuardDuty) | Three scenarios, custom threat intel set, S3 Protection |
| Incident Response | NIST phase ordering, evidence before containment, runbooks |
| IAM Least Privilege | Per-Lambda execution roles, tag-scoped remediation role |
| IAM Deny Policies | `AWSDenyAll`, `aws:TokenIssueTime` session revocation |
| Cross-account pattern | Assume-role remediation (single account, cross-account-ready) |
| CloudTrail | Multi-region trail, data events, log file validation, KMS, Athena |
| AWS Config | `s3-bucket-public-read-prohibited` |
| Security Hub | Aggregation layer, ASFF routing, workflow status updates |
| KMS (CMKs) | Three separate keys, rotation enabled, key policies |
| S3 Security | Object Lock, bucket policies, public access block |
| VPC Security | Security group isolation, connection tracking, Flow Logs |
| EventBridge | Finding routing with per-rule severity and resource scoping |
| Step Functions | Stateful orchestration, Retry/Catch, direct DynamoDB integration |

---

## 16. What Separates This From Tutorial-Level Work

| Tutorial Implementation | Argus |
|---|---|
| Single Lambda does everything | Step Functions orchestrates discrete phases |
| Contain immediately on detection | Preserve evidence first, then contain |
| Security group swap leaves live sessions open | Tested live: security groups can't end tracked connections, so a deny-all NACL cuts them |
| Deny policy only on the user | Also revokes assumed-role and instance-role sessions |
| One attack vector | Three attack vectors, unified orchestrator |
| No idempotency | Atomic conditional write keyed on the finding ID |
| Failures go unnoticed | Catch → FAILED state → escalation alert |
| Console-deployed | 100% Terraform IaC, remote state, clean teardown |
| Alert is an afterthought | Structured evidence package with SHA-256 digest |
| No documentation | Threat model, incident reports, runbooks |

---

*Specification authored June 2026, revised November 2026 (v1.1). Build with intent.*
