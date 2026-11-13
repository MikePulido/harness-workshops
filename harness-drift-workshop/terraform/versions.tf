# The workshop workspace's Terraform. Runs inside IaCM workspace drift_workshop with
# HARNESS_PLATFORM_API_KEY from the workspace environment (a Harness secret).
# It manages Harness resources only, so drift can be created by hand in the
# Harness UI with no cloud account and no cost.
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
