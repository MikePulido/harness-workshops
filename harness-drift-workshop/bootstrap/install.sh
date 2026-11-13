#!/usr/bin/env bash
# One-shot install of the drift remediation workshop into a Harness project.
#
#   HARNESS_ACCOUNT_ID=... HARNESS_API_KEY=... HARNESS_ORG_ID=... HARNESS_PROJECT_ID=... \
#   PROVIDER_CONNECTOR=<any cloud connector id> HARNESS_GIT_USERNAME=<your harness email> \
#   [MODEL_CONNECTOR=anthropic_api] [NAME_PREFIX=drift_workshop] \
#   bootstrap/install.sh
#
# Needs: tofu (or terraform >= 1.9), git, the harness CLI
# (brew install --cask harness/tap/harness-cli). Three steps:
#   1. tofu apply in bootstrap/ (repo, secret, workspace, pipelines, defaults)
#   2. push this folder to the new Code repository
#   3. harness create agent with the model connector substituted in
# Idempotent: re-running updates the pipelines, force-pushes the folder and
# updates the agent.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
kit="$(cd "$here/.." && pwd)"

for v in HARNESS_ACCOUNT_ID HARNESS_API_KEY HARNESS_ORG_ID HARNESS_PROJECT_ID PROVIDER_CONNECTOR HARNESS_GIT_USERNAME; do
  if [ -z "${!v:-}" ]; then echo "missing $v" >&2; exit 2; fi
done
MODEL_CONNECTOR="${MODEL_CONNECTOR:-anthropic_api}"
NAME_PREFIX="${NAME_PREFIX:-drift_workshop}"
TF="${TF:-tofu}"
command -v "$TF" >/dev/null || { echo "$TF not found; set TF=terraform if that is what you have" >&2; exit 2; }
command -v harness >/dev/null || { echo "harness CLI not found: brew install --cask harness/tap/harness-cli" >&2; exit 2; }

export HARNESS_PLATFORM_API_KEY="$HARNESS_API_KEY"
export TF_VAR_account_id="$HARNESS_ACCOUNT_ID" TF_VAR_org_id="$HARNESS_ORG_ID" TF_VAR_project_id="$HARNESS_PROJECT_ID"
export TF_VAR_harness_api_key="$HARNESS_API_KEY" TF_VAR_provider_connector="$PROVIDER_CONNECTOR"
export TF_VAR_git_username="$HARNESS_GIT_USERNAME" TF_VAR_model_connector="$MODEL_CONNECTOR" TF_VAR_name_prefix="$NAME_PREFIX"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
agent_id="${NAME_PREFIX}_remediation"

# The agent goes first: Harness validates an Agent step's agentName when the
# pipeline is saved, so the drift pipeline cannot be created before it exists.
echo "== 1/3 worker agent $agent_id"
sed -e "s/^\(      connector: \).*/\1${MODEL_CONNECTOR}/" -e "s/^name: .*/name: ${agent_id}/" "$kit/agents/drift-remediation.yaml" > "$tmp/agent.yaml"
export HARNESS_ACCOUNT="$HARNESS_ACCOUNT_ID"
if harness get agent "$agent_id" --org "$HARNESS_ORG_ID" --project "$HARNESS_PROJECT_ID" >/dev/null 2>&1; then
  harness update agent "$agent_id" -f "$tmp/agent.yaml" --org "$HARNESS_ORG_ID" --project "$HARNESS_PROJECT_ID"
else
  harness create agent "$agent_id" -f "$tmp/agent.yaml" --org "$HARNESS_ORG_ID" --project "$HARNESS_PROJECT_ID"
fi

echo "== 2/3 bootstrap apply"
# One local state per target, so the same checkout can install into several
# accounts, orgs or projects without the states colliding.
state_ws="${HARNESS_ACCOUNT_ID}_${HARNESS_ORG_ID}_${HARNESS_PROJECT_ID}_${NAME_PREFIX}"
(cd "$here" && "$TF" init -input=false >/dev/null && "$TF" workspace select -or-create "$state_ws" >/dev/null && "$TF" apply -input=false -auto-approve)
git_url="$(cd "$here" && "$TF" output -raw repo_git_url)"
workspace="$(cd "$here" && "$TF" output -raw workspace)"

echo "== 3/3 push the kit to $git_url"
# The repository holds Terraform only. The agent is self-contained and the
# pipeline scripts are embedded in the pipelines, so nothing else is needed.
mkdir -p "$tmp/repo"
(cd "$kit" && tar --exclude='.terraform' --exclude='*.tfstate*' --exclude='.terraform.lock.hcl' -cf - terraform README.md .gitignore) | (cd "$tmp/repo" && tar -xf -)
(
  cd "$tmp/repo"
  git init -q -b main
  git add -A
  git -c user.name="drift-workshop install" -c user.email="drift-workshop@example.invalid" commit -q -m "Drift remediation workshop kit"
  # Harness Code over HTTPS: your Harness user name and an API token, both
  # URL-encoded (an email's @ would otherwise be read as the host separator).
  enc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
  auth_url="$(printf '%s' "$git_url" | sed "s#https://#https://$(enc "$HARNESS_GIT_USERNAME"):$(enc "$HARNESS_API_KEY")@#")"
  GIT_TERMINAL_PROMPT=0 git push -q --force "$auth_url" HEAD:refs/heads/main
)

cat <<EOF

Installed. Next, in Harness:
  1. IaCM > Workspaces > $workspace > Provision (apply): creates the workshop environments and variables.
  2. Run pipeline ${NAME_PREFIX}_inject (or hand-edit a tag on environment ${NAME_PREFIX}_dev) to create drift.
  3. Workspace > Detect Drift: the agent edits terraform/, the publish step opens a pull request in the Code repo.
  4. Merge the pull request (accept the manual change) or close it and Provision again (revert it).
EOF
