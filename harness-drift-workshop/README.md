# Drift remediation workshop

## Step 1. Look at the workspace

1. Go to IaCM > Workspaces > `drift_workshop`.
2. Open its configuration. Check:
   - Provisioner: OpenTofu
   - Repository: `drift_workshop_repo`, branch `main`, folder `terraform`
   - Terraform variables: `account_id`, `org_id`, `project_id`, `name_prefix`
   - Environment variable `HARNESS_PLATFORM_API_KEY`, a secret. This is how
     the Harness Terraform provider authenticates inside the pipeline.
   - Default pipelines: Provision `drift_workshop_apply`, Destroy
     `drift_workshop_destroy`, Drift `drift_workshop_drift`
3. Go to Code > Repositories > `drift_workshop_repo` > `terraform/main.tf`.
   Read it. Two environments: `drift_workshop_dev` with tag `tier = dev`,
   `drift_workshop_prod` with `tier = prod` and `oncall = platform`. Two
   variables: `drift_workshop_banner` and `drift_workshop_replicas = 2`.

Expected: Project Settings > Environments has no `drift_workshop` environments
yet. Nothing has been applied.

## Step 2. Provision

1. On the workspace, click Provision. Harness runs `drift_workshop_apply`
   with this workspace filled in.
2. Follow the steps in the execution:
   - `init` downloads the Harness provider.
   - `plan` shows 4 to add: two environments, two variables.
   - `approve` waits. Open the step and click Approve.
   - `apply` creates the four resources.
3. Check:
   - Project Settings > Environments lists `drift_workshop dev` and
     `drift_workshop prod`.
   - Project Settings > Variables lists `drift_workshop_banner` and
     `drift_workshop_replicas`.
   - The workspace's Resources tab lists all four.

## Step 3. Detect drift with nothing drifted

1. On the workspace, click Detect Drift. Harness runs `drift_workshop_drift`.
2. Follow the steps:
   - `init`
   - `drift` passes: live state matches the code.
   - `Agent - remediate drift` and `Publish - pull request` are skipped. Both
     run only when the `drift` step fails.
3. Check: the execution succeeds. This is the baseline.

## Step 4. Create drift

Pick one.

By hand, the way drift happens in real life:

1. Project Settings > Environments > `drift_workshop dev` > Edit.
2. Change the tag `tier` from `dev` to `dev-manual-change`. Save.

Or with the pipeline:

1. Pipelines > `drift_workshop inject` > Run.
2. Keep the defaults: target `environment`, identifier `drift_workshop_dev`,
   tag `tier`, value `dev-manual-change`. Run.
3. The step log prints the value before and after.

Check: the environment's tags show `tier: dev-manual-change`. The Terraform
still says `dev`. That is drift.

## Step 5. Detect drift and watch the agent fix it

1. On the workspace, click Detect Drift.
2. Follow the steps:
   - `init`
   - `drift` fails. This is expected: the execution ends marked Failed with
     "Infrastructure drift detected". Open the step. It names
     `harness_platform_environment.this["drift_workshop_dev"]` and shows the
     tag before and after.
   - `Agent - remediate drift` runs because `drift` failed. Open its log. The
     agent finds `plan.json`, reads the drift, edits `terraform/main.tf` so
     the dev environment's own tags say `tier = "dev-manual-change"` (it
     leaves `common_tags` alone, because only dev drifted), and writes a short
     summary. It never runs apply, git or any API call. Around ten turns.
   - `Publish - pull request` commits the edit on branch
     `agent/drift/drift_workshop/<run number>`, pushes it to
     `drift_workshop_repo`, and opens a pull request. The last line of its
     log is `RESULT=opened <pull request url>`.
3. Check: Code > Repositories > `drift_workshop_repo` > Pull Requests shows
   one open pull request titled
   `drift(drift_workshop): reconcile 1 resource to live state`.

## Step 6. Review the pull request

1. Open the pull request from Step 5.
2. Read the description:
   - the agent's summary: what changed, why, what it left alone
   - Drift found: resource, attribute, value before and after
   - the link to the pipeline execution
   - the raw drift under `drift.json`
3. Open Changes. One line changed in `terraform/main.tf`.

Nothing was applied. The live environment is unchanged. Only the code changed.

## Step 7. Decide

To accept the manual change:

1. Merge the pull request.
2. On the workspace, click Detect Drift. The `drift` step passes; the agent
   and publish steps are skipped. Code and live state agree.

To reject the manual change:

1. Close the pull request.
2. On the workspace, click Provision. `plan` shows 1 to change: the tag goes
   back to `dev`. Approve. `apply` reverts the environment.
3. Click Detect Drift. Clean.

## Step 8. Again, with a variable

1. Project Settings > Variables > `drift_workshop_replicas` > change the value
   from `2` to `3`. Or run `drift_workshop inject` with target `variable`,
   identifier `drift_workshop_replicas`, value `3`.
2. Detect Drift. The pull request changes the `variables` map in
   `terraform/main.tf`.
3. Decide as in Step 7.

## Step 9. Clean up

On the workspace, click Destroy. Approve. The four resources are removed.

## How it works

```
Detect Drift
  init -> drift (fails when live != code)
       -> Agent: reads plan.json, edits terraform/, writes a summary
       -> Publish: commits, pushes, opens the pull request in Harness Code
Reviewer: merge (accept the change) or close + Provision (revert it)
```

- The agent's prompt is self-contained. Repositories never change when the
  agent does.
- The agent only edits. Agent containers get placeholder secrets, so the pull
  request is opened by a plain Run step, where secrets are real.
- Every message, tool call and result is a turn. The prompt forbids narration;
  the cap is 40, a run uses about ten.

## If something goes wrong

- `Publish - pull request` ends with `RESULT=blocked <reason>`: the reason is
  on that line. `remediation.json` in the step's artifacts has the detail.
- The pull request has no agent summary: the agent ran out of turns before
  writing it. The diff is still correct; review the Changes tab.
- `drift` passes but you changed something: the change is to an attribute the
  provider does not manage. Change a tag or a variable value.
