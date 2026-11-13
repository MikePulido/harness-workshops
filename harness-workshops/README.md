# Workshops: one command per project

Puts the same setup into a Harness project: the model and cloud connectors,
the drift remediation workshop, the DevSecOps labs 1-5 pipeline, and the
fix-one-vulnerability loop.

## Run

```
python3 harness-workshops/install.py --project <project id> --token <api key>
```

The account, org, model key and AWS keys come from `.env` at the repository
root: `WORKSHOP_ACCOUNT_ID`, `WORKSHOP_ORG_ID`, `anthropic_api_key`,
`aws-access-key`, `aws-secret-key`. The git user name defaults to
`<project>@harnessevents.com`; pass `--git-username` when the key belongs to
someone else. `--dry-run` prints what would happen. Re-running updates
everything in place.

Tools: `python3`, `git`, `tofu` (or `terraform` with `TF=terraform`), the
Harness CLI (`brew install --cask harness/tap/harness-cli`).

## What the project gets

| Kind | Identifiers |
|---|---|
| Secrets | `anthropic_api_key`, `aws_secret_key`, `drift_workshop_api_key`, `devsecops_api_key` |
| Connectors | `anthropic_api` (Anthropic, claude-sonnet-4-6), `aws_creds` (AWS, us-east-2) |
| Drift workshop | repository `drift_workshop_repo`, workspace `drift_workshop`, pipelines `drift_workshop_apply`, `drift_workshop_drift`, `drift_workshop_inject`, `drift_workshop_destroy`, agent `drift_workshop_remediation` |
| DevSecOps | service `frontend`, pipeline `workshop` (labs 1-5 plus the step group), agent `devsecops_critical_fix`, template `devsecops_critical_fix_loop` |

The lab pipeline is created when missing and otherwise left alone, so
attendee edits survive a re-run; `harness-devsecops-workshop/install.py --reset-lab`
rewrites it.

## What the project must already have

From the workshop provisioning: Code repository `harness-devsecops`, templates
`Compile_Application`, `fortify` and `owasp`, connector `dockerhub_devsecops`,
service `backend`, environment `prod` with infrastructure `k8s`, project
variable `username`. The lab pipeline uses them; nothing here creates them.

## Details

- `harness-drift-workshop/bootstrap/README.md`
- `harness-devsecops-workshop/README.md`

Tests: `python3 -m unittest discover -s harness-workshops -p 'test_*.py'`
