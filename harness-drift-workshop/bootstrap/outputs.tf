output "repo_git_url" {
  description = "HTTPS git URL of the Code repository; install.sh pushes this folder there."
  value       = harness_platform_repo.this.git_url
}

output "repo_identifier" {
  value = harness_platform_repo.this.identifier
}

output "workspace" {
  value = harness_platform_workspace.this.identifier
}

output "agent_identifier" {
  description = "Worker Agent identifier the drift pipeline references; created by install.sh with the Harness CLI."
  value       = local.agent_id
}

output "pipelines" {
  value = { for k, p in harness_platform_pipeline.this : k => p.identifier }
}

output "api_key_secret" {
  value = harness_platform_secret_text.api_key.identifier
}
