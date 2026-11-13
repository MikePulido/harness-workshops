# Fix one vulnerability per run, with a Worker Agent

Adds a step group to the DevSecOps workshop pipeline. After the lab's scans,
an OSV scan finds real dependency vulnerabilities, a Worker Agent fixes
exactly one of them, the most severe it can, by changing one line, and a pull
request opens in the Harness Code repository. Run the pipeline again and the
next one gets its pull request. Everything stays in Harness.

```
Build stage
  ... Run Tests, Compile, Fortify, Push to DockerHub, OWASP
  Fix one vulnerability (step group template)
    osv       OSV-Scanner, orchestration, results in the Vulnerabilities tab
    findings  Run step: the OSV scan's issues, one per vulnerability, every severity, plus the OSV records behind each -> findings.json; notes what the workspace already contains. Data only.
    remediate Worker Agent: picks the finding, finds the pin, picks the version, changes one line, writes summary.md
    publish   Run step: one line in one manifest and nothing else? a real finding? OSV says closed? lockfile; commit, push, pull request
```

The lab's OWASP and Fortify steps ingest canned reports from another project,
so their findings cannot be fixed in this code. The OSV scan is what makes the
findings real. The agent decides; the scripts only fetch data and enforce the
rule.

## Facilitator: install

Prerequisites: `python3`, the Harness CLI
(`brew install --cask harness/tap/harness-cli`), an Anthropic model connector
in the project, and the workshop pipeline from labs 1-5 already saved.

1. Export the inputs.

   ```
   export HARNESS_ACCOUNT_ID=...
   export HARNESS_API_KEY=...            # PAT or SAT with STO, Code, Pipeline and Template rights
   export HARNESS_ORG_ID=...
   export HARNESS_PROJECT_ID=...
   export HARNESS_GIT_USERNAME=...       # email the key belongs to
   export MODEL_CONNECTOR=anthropic_api
   # optional: NAME_PREFIX=devsecops REPO=harness-devsecops PIPELINE_ID=workshop
   ```

2. Run the installer.

   ```
   python3 install.py
   ```

   It creates the lab's service `frontend` and pipeline `workshop` from
   `lab/` when they are missing (`--reset-lab` rewrites the pipeline,
   `--no-lab` skips both), then the Worker Agent `<prefix>_critical_fix`,
   the secret `<prefix>_api_key`, the step group template
   `<prefix>_critical_fix_loop` v0.1 (shown as "`<prefix>` fix one
   vulnerability"; the agent occupies the shorter identifier as a Step
   template), and appends the step group to the Build stage of the pipeline.
   Re-running updates everything. `--no-pipeline` skips the last step;
   attendees then add it themselves with Use Template.

   To set up a whole project in one go (connectors, drift workshop, this),
   use `python3 harness-workshops/install.py` from the repository root.

## Lab: fix one vulnerability with a Worker Agent

1. Open the `workshop` pipeline. In the Build stage, after OWASP, find the
   step group `Critical fix`. Expand it: OSV scan, Findings, Agent, Publish.
   If it is not there: click `+` after OWASP, Use Template, Step Group,
   `devsecops fix one vulnerability`.
2. Run the pipeline on `main`.
3. Follow the four steps:
   - `OSV scan`: open the Vulnerabilities tab. These are real findings in
     `backend/requirements.txt` and the frontend lockfile.
   - `Findings`: one line per vulnerability, highest CVSS first, with the
     versions OSV says fix it; a package with several appears several times.
     No decision is made here; this is the agent's input.
   - `Agent - fix one vulnerability`: the agent reads `findings.json`,
     decides which finding a single pinned line can fix, finds that line
     with one grep, picks the smallest version that closes the finding,
     edits, and writes its summary. Around eight turns.
   - `Publish - pull request`: the log shows the verification, the commit on
     `agent/fix/<package>/<run>`, and ends with `RESULT=opened <url>`.
4. Open Code > Repositories > `harness-devsecops` > Pull Requests. Read the
   description: the agent's summary, the finding with its ids, the OSV
   re-check, and the other findings still open. Changes: one line.
5. Merge it. Run the pipeline again: the next vulnerability gets its own pull
   request, sometimes on the same package. Keep going as long as you like.
   Close one instead of merging and the same finding comes back next run.

What to try next:

- Change two lines by hand on a branch and run: `Publish` blocks with the
  reason. The rule is enforced by the pipeline, not only by the prompt.
- Set `MIN_SEVERITY` to `Critical` in the template to narrow the pool.
- `SCANNER` names the STO product the findings come from (`osv-scanner`).
  Point it at another scanner in the stage and the agent works from that
  scan instead.
- Open the agent in the catalog and change a rule, for example prefer the
  frontend, or allow a major bump. Run again and compare the pull requests.
  The choice of finding and version lives in the prompt, not in a script.

## Layout

```
agents/      the Worker Agent definition (CLI format)
lab/         the labs 1-5 service and pipeline, with tokens for org, project and repository
scripts/     findings.py (data in) and publish.py (rule out), embedded into the template; test_scripts.py
templates/   the step group template, with tokens install.py fills
install.py   agent, secret, template, pipeline patch; --render prints the template
```

Tests: `python3 -m unittest discover -s scripts -p 'test_*.py'`
