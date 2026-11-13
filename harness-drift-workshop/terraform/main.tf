# What the workshop drifts. Two environments and two project variables, each
# built from a map and a merge() so that reconciling a drifted value is a
# small decision rather than a copy: a changed tag on one environment belongs
# as an override in that environment's entry, not in common_tags, and a
# changed variable value belongs in the variables map.
#
# To create drift by hand: Project Settings > Environments > <prefix>_dev >
# edit a tag; or Project Settings > Variables > <prefix>_replicas > change the
# value. Or run the <prefix>_inject pipeline, which does the same through the
# API.
locals {
  common_tags = {
    managedby = "harness-iacm"
    workshop  = "drift"
  }

  environments = {
    "${var.name_prefix}_dev" = {
      name = "${var.name_prefix} dev"
      type = "PreProduction"
      tags = { tier = "dev" }
    }
    "${var.name_prefix}_prod" = {
      name = "${var.name_prefix} prod"
      type = "Production"
      tags = { tier = "prod", oncall = "platform" }
    }
  }

  variables = {
    "${var.name_prefix}_banner"   = { value = "hello from terraform" }
    "${var.name_prefix}_replicas" = { value = "2" }
  }
}

resource "harness_platform_environment" "this" {
  for_each = local.environments

  identifier  = each.key
  name        = each.value.name
  org_id      = var.org_id
  project_id  = var.project_id
  type        = each.value.type
  description = "Drift remediation workshop environment; edit a tag here to create drift"
  tags        = [for k, v in merge(local.common_tags, each.value.tags) : "${k}:${v}"]
}

resource "harness_platform_variables" "this" {
  for_each = local.variables

  identifier  = each.key
  name        = each.key
  org_id      = var.org_id
  project_id  = var.project_id
  type        = "String"
  description = "Drift remediation workshop variable; change the value here to create drift"

  spec {
    value_type  = "FIXED"
    fixed_value = each.value.value
  }
}
