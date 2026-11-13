# Harness workshops

This repository installs the same workshop setup into any Harness event project with one command. A project ends up with the model and cloud connectors, the drift remediation workshop, and the DevSecOps labs 1-5 pipeline. It also gets a loop in which a Worker Agent fixes one vulnerability and opens a pull request.

## Install a project

Copy the sample env file, fill it in, and run the installer with the project identifier and that project's personal access token.

```
cp .env.example .env
python3 harness-workshops/install.py --project <project id> --token <personal access token>
```

The installer is idempotent. Run it again and it updates everything in place, so a failed project can be retried on its own.

Three flags change what a run does.

- **Dry run.** `--dry-run` prints the plan and makes no calls.
- **One kit only.** `--no-drift` or `--no-devsecops` skips the other.
- **Different key owner.** `--git-username` sets the email the token belongs to. It defaults to the project user's event address.

The machine needs python3, git, OpenTofu and the Harness command line interface. Terraform 1.9 or newer works instead of OpenTofu when the TF environment variable names it. Install the CLI with Homebrew.

```
brew install --cask harness/tap/harness-cli
```

The project must already contain what the event provisioning creates, such as the DevSecOps Code repository and the scan templates. The installer creates none of those. The full list is in [harness-workshops/README.md](harness-workshops/README.md).

## What is in here

- **harness-workshops/** holds the one-command installer. It creates the secrets and connectors, then runs the two kits below.
- **harness-drift-workshop/** is the drift workshop for Infrastructure as Code Management. It gives a project a Code repository, a workspace and pipelines for apply, drift, inject and destroy. A Worker Agent rewrites the Terraform when drift is found.
- **harness-devsecops-workshop/** is the DevSecOps workshop. It creates the labs 1-5 service and pipeline, then appends a step group. That group scans with Open Source Vulnerabilities, has a Worker Agent fix one finding, and opens a pull request.
- **tests/** holds Jest tests that render every template, check both agent definitions, and run the three Python unittest suites.

Each kit has a facilitator guide. The drift guide is [harness-drift-workshop/bootstrap/README.md](harness-drift-workshop/bootstrap/README.md). The DevSecOps guide is [harness-devsecops-workshop/README.md](harness-devsecops-workshop/README.md). The attendee README for the drift workshop is at that kit's root. The installer pushes it into the project's Code repository.

## How it installs

Everything goes through the Harness REST API with one personal access token per project. Three mechanisms share that token.

- **Plain REST calls** from the Python installers create the secrets, connectors, lab service, lab pipeline and step group template. The same path patches the step group into the pipeline without touching attendee edits.
- **OpenTofu with the Harness provider** creates the drift kit's repository, secret, four pipelines and workspace. It orders the dependencies between them and removes them all on destroy.
- **The Harness CLI** creates the two Worker Agents, because agents have no Terraform resource.

OpenTofu state is local, one workspace per target, under `harness-drift-workshop/bootstrap/terraform.tfstate.d/`. The state holds the project token in plaintext, so git ignores it. Keep the directory, because tear-down reads it. Tear down from one checkout only.

Run the tests after any change.

```
npm install
npm test
npm run test:python
```

The Jest run also executes the Python suites. The last command runs the Python suites alone.
