# Test events

These are **synthetic** EventBridge input-transformer outputs, shaped from the AWS
documentation of ASFF. They are what each state machine receives as input.

Phase 3 of the build plan replaces them with **real** captured events: run a
simulation, copy the execution input from the Step Functions console (or the raw
Security Hub event from a stub target), and save it here as `*.real.json`.
Then re-run the tests and adjust `envelope.py` and the EventBridge patterns if the
real field paths differ (especially `Types` and `Resources[].Details.AwsIamAccessKey`).
