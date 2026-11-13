# Bootstrap for the drift remediation workshop. Run once per Harness project, from
# a workstation, with the Harness provider authenticated by
# HARNESS_PLATFORM_API_KEY. It creates everything the workshop needs inside the
# target project and nothing outside it:
#
#   - a Harness Code repository holding this folder
#   - a secret with the API key the workshop workspace's own Terraform runs with
#   - the IaCM workspace drift_workshop, pointed at terraform/ in that repository
#   - four inline pipelines: apply, destroy, drift (with the agent) and inject
#   - the workspace-level default pipelines, so the workspace's own buttons
#     run them without touching the project's defaults
#
# The Worker Agent has no provider resource; bootstrap/install.sh creates it
# with the Harness CLI after the apply, and pushes this folder to the repo.
terraform {
  required_version = ">= 1.9.0"

  required_providers {
    harness = {
      source  = "harness/harness"
      version = "~> 0.45"
    }
  }
}

provider "harness" {
  endpoint   = var.harness_endpoint
  account_id = var.account_id
}
