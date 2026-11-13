# Facilitator: install and tear down

The root `README.md` is what attendees read; it is pushed to the Code
repository. This file is for whoever installs the workshop.

## What is installed

Every identifier starts with `drift_workshop` (change it with `NAME_PREFIX`).

| Resource | Identifier | Role |
|---|---|---|
| Code repository | `drift_workshop_repo` | Holds `terraform/` and the attendee README. The pull requests land here. |
| IaCM workspace | `drift_workshop` | Reads `terraform/` on `main` of that repository. |
| Pipeline | `drift_workshop_apply` | Provision: init, plan, approve, apply |
| Pipeline | `drift_workshop_drift` | Detect Drift: init, detect-drift, AI agent, publish pull request |
| Pipeline | `drift_workshop_inject` | Creates drift through the API (alternative to a hand edit) |
| Pipeline | `drift_workshop_destroy` | Destroy: init, plan-destroy, approve, destroy |
| Worker Agent | `drift_workshop_remediation` | The AI agent that edits the Terraform |
| Secret | `drift_workshop_api_key` | API key used by the workspace, the publish step and the inject step |

## Prerequisites

- `tofu` (or `terraform` 1.9+ with `TF=terraform`), `git`, `python3`
- Harness CLI: `brew install --cask harness/tap/harness-cli`
- In the target project: an Anthropic model connector (type Anthropic, token
  secret, model `claude-sonnet-4-6`), and any cloud connector (IaCM requires
  one on every workspace; the workshop never uses it)
- An API key with IaCM, Code, Environment and Variable permissions, and the
  email of the user or service account it belongs to

## Install

1. Export the inputs.

   ```
   export HARNESS_ACCOUNT_ID=...
   export HARNESS_API_KEY=...
   export HARNESS_ORG_ID=...            # identifier, lowercase
   export HARNESS_PROJECT_ID=...
   export PROVIDER_CONNECTOR=...        # any cloud connector id
   export HARNESS_GIT_USERNAME=...      # email the key belongs to
   export MODEL_CONNECTOR=anthropic_api
   ```

2. Run the installer.

   ```
   bootstrap/install.sh
   ```

   It creates the Worker Agent, then the repository, secret, workspace and
   pipelines, then pushes `terraform/` and the attendee README to the
   repository. Re-running it updates everything in place, including the
   README after an edit.

3. Open IaCM > Workspaces and confirm `drift_workshop` is listed.

To set up a whole project in one go (connectors, this kit, the DevSecOps
kit), use `python3 harness-workshops/install.py` from the repository root.

Terraform state is local, one per target: `terraform.tfstate.d/<account>_<org>_<project>_<prefix>/`.
One checkout can hold installs into several accounts.

## Tear down

1. Attendees run Step 9 (workspace Destroy), which removes the four managed
   resources.
2. With the same inputs exported, in this directory:

   ```
   tofu workspace select <account>_<org>_<project>_drift_workshop
   tofu destroy
   ```

   This removes the repository, workspace, pipelines and secret. The Worker
   Agent stays in the catalog (the CLI cannot delete agents); delete it in the
   UI if wanted.

## Layout

```
bootstrap/   install.sh, Terraform for the Harness resources, publish.py and inject.py (embedded into the pipelines)
terraform/   what the workspace manages; pushed to the Code repository with the root README
pipelines/   apply, destroy, drift, inject templates
agents/      the Worker Agent definition
```

Tests: `python3 -m unittest discover -s bootstrap -p 'test_*.py'`
