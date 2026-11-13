variable "account_id" {
  type = string
}

variable "org_id" {
  type = string
}

variable "project_id" {
  type = string
}

variable "name_prefix" {
  description = "Prefix for every identifier; matches the bootstrap's name_prefix."
  type        = string
  default     = "drift_workshop"
}

variable "harness_endpoint" {
  type    = string
  default = "https://app.harness.io/gateway"
}
