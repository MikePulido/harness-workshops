# Harness workshops

Everything needed to put the same workshop setup into a Harness project, the
same way every time: the model and cloud connectors, the drift remediation
workshop, the DevSecOps labs 1-5 pipeline, and the fix-one-vulnerability loop.

## One command per project

```
cp .env.example .env            # fill in account, org, model key, AWS keys
python3 harness-workshops/install.py --project <project id> --token <that project's PAT>
```

`--dry-run` prints the plan. Re-running updates everything in place, so a
failed project can be retried alone. `--no-drift` and `--no-devsecops` skip a
kit. Details and the list of what a project must already have:
[harness-workshops/README.md](harness-workshops/README.md).

Tools: `python3`, `git`, `tofu` (or `terraform` 1.9+ with `TF=terraform`),
and the Harness CLI (`brew install --cask harness/tap/harness-cli`).

## Layout

| Folder | What it is |
|---|---|
| `harness-workshops/` | The one-command installer: secrets, connectors, then the two kits below |
| `harness-drift-workshop/` | IaCM drift remediation: Code repo, workspace, apply/drift/inject/destroy pipelines, Worker Agent. Installed with OpenTofu against the Harness provider |
| `harness-devsecops-workshop/` | DevSecOps labs 1-5 (service `frontend`, pipeline `workshop`) plus the step group that scans with OSV, has a Worker Agent fix one vulnerability, and opens a pull request |
| `tests/` | Jest tests that render the templates and run every Python unittest suite |

Facilitator docs per kit:
[harness-drift-workshop/bootstrap/README.md](harness-drift-workshop/bootstrap/README.md),
[harness-devsecops-workshop/README.md](harness-devsecops-workshop/README.md).
The attendee README for the drift workshop is
[harness-drift-workshop/README.md](harness-drift-workshop/README.md); the
installer pushes it into the project's Code repository.

## How it installs

Three mechanisms, all against the Harness REST API with one personal access
token per project:

- Plain REST from the Python installers for secrets, connectors, the lab
  service and pipeline, the step group template, and the pipeline patch.
- OpenTofu with the Harness Terraform provider for the drift kit's repo,
  secret, four pipelines and IaCM workspace. State is local, one workspace
  per target under `harness-drift-workshop/bootstrap/terraform.tfstate.d/`,
  and it holds the project's token in plaintext, so it is git-ignored. Keep
  it: tear-down (`tofu destroy`) needs it.
- The Harness CLI for the two Worker Agents, which have no Terraform
  resource.

## Tests

```
npm install
npm test            # Jest: renders templates, checks agents, runs the Python suites
npm run test:python # the three unittest suites on their own
```
