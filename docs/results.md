# Argus — Measured Results

Live results from the deployment in us-east-1 on 2026-11-16 (single account, all three
scenarios triggered by real GuardDuty findings), plus a second verification round the same
night that tested every claim the first round left open. Every number below was read back from
AWS: Step Functions execution histories, the `argus-incidents` table, the evidence
bundles in S3, and the AWS APIs named in each check. Account IDs are redacted.

## Headline numbers

| Metric | Result | Spec target |
|---|---|---|
| Time to contain (finding received → containment complete), 6 real incidents | **median 8 s, max 11 s** (5, 6, 8, 8, 10, 11 s) | < 60 s ✅ |
| GuardDuty finding → Argus, new findings | 13–23 s | (measured separately, as the spec requires) |
| GuardDuty finding → Argus, updates to existing findings | ~3 min (185 s, 198 s) | — |
| Attack started → resource contained, new findings | 3 min 14 s – 3 min 58 s (EC2), ~4 min (S3) | — |
| Attack started → resource contained, IAM | 9 min 49 s (GuardDuty took ~9½ min to raise this one) | — |
| Evidence digests verified (`sha256sum`) | **7 / 7** bundles, **6 / 6** supplemental files | ✅ |
| Double containment of one resource | **0** (18 duplicates and 21 re-deliveries absorbed) | ✅ |
| Failures that went unreported | **0** (6 failures → 6 alert emails) | ✅ |

Detection latency is dominated by GuardDuty, which Argus doesn't control. The containment
time is what Argus controls, and it never exceeded 11 seconds.

## Completed incidents

| Scenario | Finding | Sev | Time to contain | Finding → Argus | Actions | Late evidence collected |
|---|---|---|---|---|---|---|
| IAM (smoke test, synthetic finding) | UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom | MEDIUM | 8 s | — | 9 | 0 CloudTrail events (user had made no calls) |
| EC2, run 1 | CryptoCurrency:EC2/BitcoinTool.B!DNS | HIGH | 8 s | 15.6 s | 11 | 478 VPC Flow Log records |
| EC2, run 2 | CryptoCurrency:EC2/BitcoinTool.B!DNS | HIGH | 10 s | (pre-fix value, not comparable) | 11 | 461 VPC Flow Log records |
| EC2, run 3 | CryptoCurrency:EC2/BitcoinTool.B!DNS | HIGH | 11 s | 185 s (finding update) | 11 | 756 VPC Flow Log records |
| S3 | Discovery:S3/MaliciousIPCaller.Custom | HIGH | 6 s | 13.2 s | 10 | 230 S3 data events (Athena) |
| IAM | UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom | MEDIUM | 5 s | 22.9 s | 9 | 14 CloudTrail events |
| IAM, chained from S3 (`argus-sim-exfil`) | Discovery:S3/MaliciousIPCaller.Custom | HIGH | 8 s | 198 s (finding update) | 9 | pending at time of writing |

All evidence objects are under S3 Object Lock (GOVERNANCE mode, 1-day retention in this
dev deployment).

## Where the time goes (median per phase, 7 full runs)

| Phase | Median | Max |
|---|---|---|
| ValidateFinding | 0.13 s | 0.46 s |
| RecordIncident (DynamoDB conditional put) | 0.14 s | 0.35 s |
| LockResource (DynamoDB conditional put) | 0.13 s | 0.17 s |
| PreserveEvidence | 3.7 s | 5.0 s |
| Contain | 2.5 s | 4.9 s |
| Eradicate | 1.6 s | 1.9 s |
| PackageEvidence | 2.1 s | 2.9 s |
| Finalize | 2.2 s | 2.4 s |
| Notify | 2.3 s | 2.7 s |

Evidence preservation is the single largest step. That's the cost of collecting forensics
*before* containment, and it is still only about 4 seconds.

## Every execution, by outcome

| Playbook | Full run | Duplicate (resource locked) | Already handled (same occurrence) | Failed → alerted |
|---|---|---|---|---|
| EC2 | 3 | 11 | 11 | 6 |
| S3 | 1 | 7 | 8 | 0 |
| IAM | 3 (+1 chained, still in late-evidence wait) | 0 | 2 | 0 |

The 6 EC2 failures all came from the first live run, before the per-resource lock existed
(see "Defects found by live testing"). "Already handled" executions are mostly the events
Security Hub emits for Argus's own RESOLVED updates, stopped at the first DynamoDB check.

## Spec claims, checked

✅ verified live · 🟡 partly verified · ❌ not verified yet

### Goals (spec §1)

| Claim | Status | Evidence |
|---|---|---|
| 100% of infrastructure via Terraform | ✅ for Argus itself | 147 resources from Terraform; `terraform plan -detailed-exitcode` reports no drift after all tests. Account prerequisites were manual by necessity: IAM Identity Center setup, and confirming the SNS email subscription |
| Phase order Preserve → Contain → Eradicate → Notify | ✅ | Order confirmed in every full execution history |
| Severity-based routing | ✅ | MEDIUM (IAM), HIGH (EC2, S3 Discovery) and LOW (S3 Policy, scoped to one bucket) all reached their state machines |
| Idempotency guards | ✅ | 21 re-deliveries stopped at RecordIncident, 18 duplicates stopped at LockResource; no resource was contained twice |
| Cross-account-ready assume-role pattern | ✅ in one account | Every remediation call made through `argus-remediation-role` |
| Under 60 s to containment | ✅ | Max 11 s |
| Budget guardrail | 🟡 | Budget alarm created; never triggered; teardown not yet tested |

### Detection (spec §6)

| Claim | Status | Evidence |
|---|---|---|
| GuardDuty + custom threat list produce the `.Custom` findings | ✅ | IAM and S3 findings raised from the threat-list IP |
| GuardDuty DNS detection of mining pools | ✅ | 7 BitcoinTool.B!DNS findings on the first run |
| CloudTrail log file validation | ✅ | `aws cloudtrail validate-logs`: 2/2 digest files valid, 49/49 log files valid |
| S3 data events queryable via Athena | ✅ | 230 data events returned for the S3 incident |
| VPC Flow Logs collected after containment | ✅ | 461–756 records per EC2 incident |
| Config rule `s3-bucket-public-read-prohibited` as a second signal | ✅ | Flagged the public bucket NON_COMPLIANT in 45 s (first test) and 183 s (second); FAILED finding imported into Security Hub |
| Config finding triggers containment | ✅ (added in round 2) | The Config finding started the S3 playbook 19 s after Config flagged the bucket: exposure fell from 618 s (GuardDuty only) to 218 s |

### Routing and orchestration (spec §7–8)

| Claim | Status | Evidence |
|---|---|---|
| EventBridge patterns match real ASFF findings | ✅ | All four rules fired on real findings; one real event saved as a test fixture |
| Failure path alerts a human | ✅ | 6 live failures → 6 FAILED emails |
| Task timeouts route to the failure path | ✅ | Throwaway state machine, real late-evidence Lambda with a 1 s task timeout: `States.Timeout` caught with `ResultPath: $.error`, the same Catch as MarkFailed |
| A FAILED incident is retried and completes | ✅ | A FAILED EC2 incident re-run after a fix completed every phase |
| Late evidence 15 minutes later, with its own digest | ✅ | 6 supplemental files, all digests valid |

### Playbooks (spec §9)

| Claim | Status | Evidence |
|---|---|---|
| IAM: deactivate keys + attach AWSDenyAll | ✅ | Both simulation users contained live |
| IAM: revoke assumed-role sessions (TokenIssueTime) | ✅ | The backdoor user assumed `argus-sim-app-role`; forensics found the `AssumeRole` in CloudTrail; afterwards the attacker's 12-minute-old role session got "explicit deny" |
| IAM: delete console password | 🟡 | Live runs correctly skipped it (no password set); deletion itself is unit-tested |
| EC2: isolate security group on every ENI | ✅ | Blocks new connections. **Does not end existing ones** (see below) |
| EC2: **live connections are actually cut** | ✅ after a fix | Original claim (untrack → isolate cuts them) was **false**. The deny-all NACL now cuts a live session within ~1–2 s, before the stop takes effect |
| EC2: instance profile detached + instance-role sessions revoked | ✅ | Role credentials copied from IMDS worked from outside AWS before containment, `AccessDenied` after |
| EC2: termination protection, stop, forensic snapshot | ✅ | Confirmed after each run; one snapshot per incident |
| S3: Block Public Access, drop policy, quarantine, versioning | ✅ | Confirmed live; the attacker's 10 later read attempts were all denied |
| S3: chain into IAM for the calling user | ✅ | `argus-sim-exfil` contained via a chained IAM execution |
| Evidence bundle + SHA-256 under Object Lock | ✅ | 7/7 digests valid, GOVERNANCE retention on every object |
| SNS escalation by severity | ✅ | Success emails (MEDIUM and HIGH) and failure emails received |
| Discord webhook | ✅ | Alert posted to Discord (HTTP 2xx); success and failure embeds received |

### Security controls (spec §10–11)

| Claim | Status | Evidence |
|---|---|---|
| Remediation role can only act on simulation resources | ✅ | IAM policy simulator: allowed on simulation targets; denied for a non-simulation user, a non-simulation bucket, an untagged instance, `TerminateInstances`, and attaching any policy other than AWSDenyAll |
| Least privilege works in practice | ✅ | Every live phase succeeded with the scoped roles (no AccessDenied in any successful run) |
| Three CMKs with rotation | ✅ | `get-key-rotation-status`: true for all three |

### Cost (spec §12)

| Claim | Status | Evidence |
|---|---|---|
| "Tens of dollars a month" | ❌ | Cost Explorer had no data yet (it lags up to 24 h). Recheck after a few days |

## Round 2: the live-connection test

A Session Manager session printing a timestamp every 2 s was held open from outside AWS
while the instance was isolated. No stop happened in phases 1–4, so the network control was
the only variable.

| Method | Session afterwards |
|---|---|
| Swap straight to the empty isolate security group | Survived 75 s+ |
| Allow-all "untrack" group, then isolate (the v1.1 playbook) | Survived 75 s+ |
| Untrack, 30 s of traffic, then isolate | Survived 60 s+ |
| Deny-all NACL on the subnet | **Cut within ~2 s** |
| Full playbook after the fix (real finding, retried) | NACL at 23:51:20, last line 23:51:21, stop called 23:51:23: cut by the NACL |

Security groups are stateful: a flow tracked when it started stays allowed whatever the
rules become, and the untrack trick doesn't change that for existing flows. In v1.1 live
sessions only ended because the instance was then stopped. The playbook now uses a
pre-provisioned deny-all NACL on subnets tagged `argus:dedicated-subnet=true`; on shared
subnets it relies on the stop.

## Defects found by live testing

Unit tests (moto) passed throughout; each of these only appeared against real AWS.

1. **Finding storms.** GuardDuty raised one finding per mining domain (7 for one
   instance); seven playbooks ran at once and six hit EC2's per-volume snapshot rate limit.
   Fix: a per-resource DynamoDB lock, plus snapshot backoff.
2. **Stopped instance replaced by Terraform.** Stopping releases the public IP, which
   Terraform read as drift forcing replacement of the quarantined instance. Fix: ignore that attribute.
3. **Recurrences ignored.** GuardDuty updates the same finding when activity recurs, and
   Argus skipped resolved findings, so a repeat attack after recovery never triggered. Fix:
   one incident per finding occurrence (ID + UpdatedAt).
4. **Wrong detection latency for recurring findings.** Measured from first creation. Fix:
   measure from UpdatedAt.
5. **Attacker left active on a duplicate.** An admin call won the bucket lock, so the
   finding naming the real attacker was a duplicate and that user was never contained.
   Fix: duplicate S3 findings still chain the IAM playbook for their actor.
6. **The untrack trick doesn't cut live connections** (round 2). Fix: deny-all NACL on
   dedicated subnets; untrack group removed (it briefly allowed all traffic).
7. **NACL step lacked a permission.** `ReplaceNetworkAclAssociation` is also authorized
   against the subnet. Caught by the failure path (4 alerts). Fix: allow it on subnets
   tagged as dedicated.
8. **Failure alert overstated the damage.** It said "NOT contained" when part of the failed
   step had already run. Fix: it now lists completed phases and warns about partial steps.
9. **A Terraform change could silently disable alerts.** Updating the webhook parameter's
   key would have re-put it with the "disabled" placeholder. Fix: ignore that attribute.
10. **Slow closure of public buckets.** GuardDuty's update took ~10 min to reach Argus
    while Config knew in under a minute. Fix: route the Config finding (618 s → 218 s).

## Still open

- **Cost:** recheck in Cost Explorer after 24 h.
- **Teardown:** `terraform destroy` not yet run.
- Config only re-evaluates on a configuration change it records; after a reset it may need
  `aws configservice start-config-rules-evaluation` before a repeat test.

## Resume bullet numbers

- "Containing three distinct attack vectors in under **11 seconds** from finding receipt"
  (median 8 s across 6 live incidents).
- "Detection-to-containment pipeline verified end to end against real GuardDuty findings,
  with 7/7 evidence digests verifiable via `sha256sum`."
- "Disproved a widely cited isolation technique with a controlled live test and replaced
  it with stateless NACL isolation, cutting live attacker sessions in ~2 seconds."
- "Cut public-bucket exposure from 10 minutes to under 4 by adding AWS Config as a
  second detection path."
- Assumed-role and stolen instance-credential revocation are now demonstrated live.
