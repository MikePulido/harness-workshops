variable "account_id" {
  description = "Harness account identifier."
  type        = string
}

variable "org_id" {
  description = "Organization the workshop is installed into."
  type        = string
}

variable "project_id" {
  description = "Project the workshop is installed into. Everything is created at this scope."
  type        = string
}

variable "harness_endpoint" {
  description = "Harness API endpoint for the provider."
  type        = string
  default     = "https://app.harness.io/gateway"
}

variable "harness_api_url" {
  description = "Harness base URL the pipelines call (Code API, NG API)."
  type        = string
  default     = "https://app.harness.io"
}

variable "harness_api_key" {
  description = "Platform API key (PAT or service account token) stored as the workshop secret. The workshop workspace's Terraform and the publish/inject steps authenticate with it, so it needs: IaCM workspace view, Code repo push and pull request write, Environment and Variable edit in this project."
  type        = string
  sensitive   = true
}

variable "model_connector" {
  description = "Identifier of the Anthropic model connector the Worker Agent uses. Assumed to exist already."
  type        = string
  default     = "anthropic_api"
}

variable "provider_connector" {
  description = "Identifier of any cloud connector in the project. IaCM requires a provider connector on every workspace; the workshop never uses it, since its Terraform manages Harness resources only."
  type        = string
}

variable "git_username" {
  description = "Harness user name (email for a user, identifier for a service account) that pairs with harness_api_key for git over HTTPS to Harness Code. Used only as the fallback push credential."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every identifier the bootstrap creates, so several installs can coexist in one project."
  type        = string
  default     = "drift_workshop"
}

variable "provisioner_version" {
  description = "OpenTofu version for the workspace."
  type        = string
  default     = "latest"
}

variable "repo_branch" {
  description = "Branch of the Code repository the workspace reads and the pull requests target."
  type        = string
  default     = "main"
}
