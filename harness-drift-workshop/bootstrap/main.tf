locals {
  repo_id        = "${var.name_prefix}_repo"
  workspace_id   = var.name_prefix
  secret_id      = "${var.name_prefix}_api_key"
  agent_id       = "${var.name_prefix}_remediation"
  tags           = { managedby = "drift-workshop" }
  tag_list       = [for k, v in local.tags : "${k}:${v}"]
  pipeline_files = { apply = "apply", destroy = "destroy", drift = "drift", inject = "inject" }

  # Values substituted into pipelines/*.yaml.tftpl. Harness expressions
  # (<+...>) pass through untouched; only ${...} placeholders are replaced.
  template_vars = {
    prefix         = var.name_prefix
    org_id         = var.org_id
    project_id     = var.project_id
    repo           = local.repo_id
    git_url        = harness_platform_repo.this.git_url
    git_username   = var.git_username
    api_key_secret = local.secret_id
    api_url        = var.harness_api_url
    agent_name     = local.agent_id
    repo_branch    = var.repo_branch
    # The pipeline scripts ship with the pipeline, embedded as heredocs, so
    # the repository a workspace reads needs nothing but Terraform.
    publish_py = file("${path.module}/publish.py")
    inject_py  = file("${path.module}/inject.py")
  }
}

# The repository that holds this folder. install.sh pushes the content after
# the apply; the workspace reads terraform/ from it and the agent runs
# scripts/ from its clone.
resource "harness_platform_repo" "this" {
  identifier     = local.repo_id
  org_id         = var.org_id
  project_id     = var.project_id
  default_branch = var.repo_branch
  description    = "Drift remediation workshop: Terraform for Harness resources, the remediation scripts and the agent definition"
}

# The key the workshop's own Terraform (terraform/) authenticates with inside the
# workspace, and the key the publish and inject steps use. One key, one secret.
resource "harness_platform_secret_text" "api_key" {
  identifier                = local.secret_id
  name                      = local.secret_id
  org_id                    = var.org_id
  project_id                = var.project_id
  description               = "Drift workshop: platform API key for the workspace's Terraform and the pipeline steps"
  secret_manager_identifier = "harnessSecretManager"
  value_type                = "Inline"
  value                     = var.harness_api_key
}

resource "harness_platform_pipeline" "this" {
  for_each = local.pipeline_files

  identifier = "${var.name_prefix}_${each.key}"
  name       = "${var.name_prefix} ${each.key}"
  org_id     = var.org_id
  project_id = var.project_id
  yaml       = templatefile("${path.module}/../pipelines/${each.value}.yaml.tftpl", local.template_vars)
}

resource "harness_platform_workspace" "this" {
  identifier  = local.workspace_id
  name        = local.workspace_id
  description = "Drift remediation workshop. Manages a few Harness environments and variables in this project; hand-edit one of them to create drift."
  org_id      = var.org_id
  project_id  = var.project_id
  tags        = local.tag_list

  provisioner_type    = "opentofu"
  provisioner_version = var.provisioner_version

  # A Harness Code repository in the same project: no repository connector.
  repository        = harness_platform_repo.this.identifier
  repository_branch = var.repo_branch
  repository_path   = "terraform"

  provider_connector      = var.provider_connector
  cost_estimation_enabled = false

  # Workspace-level defaults, so the Provision, Destroy and Detect Drift
  # buttons on this workspace run the workshop pipelines while every other
  # workspace in the project keeps the project's own defaults.
  default_pipelines = {
    apply   = harness_platform_pipeline.this["apply"].identifier
    destroy = harness_platform_pipeline.this["destroy"].identifier
    drift   = harness_platform_pipeline.this["drift"].identifier
  }

  terraform_variable {
    key        = "account_id"
    value      = var.account_id
    value_type = "string"
  }

  terraform_variable {
    key        = "org_id"
    value      = var.org_id
    value_type = "string"
  }

  terraform_variable {
    key        = "project_id"
    value      = var.project_id
    value_type = "string"
  }

  terraform_variable {
    key        = "name_prefix"
    value      = var.name_prefix
    value_type = "string"
  }

  environment_variable {
    key        = "HARNESS_PLATFORM_API_KEY"
    value      = harness_platform_secret_text.api_key.identifier
    value_type = "secret"
  }
}
