# External executor authority only. This stack does not silently create or
# charge for a Kubernetes cluster; provision/qualify the selected cluster first.
variable "executor_kubeconfig_secret_arn" {
  description = "Secrets Manager ARN containing a one-context flattened JSON kubeconfig with inline TLS credentials, scoped only to the dedicated execution namespace."
  type        = string
  default     = ""
  validation {
    condition     = var.executor_kubeconfig_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:", var.executor_kubeconfig_secret_arn))
    error_message = "Executor credentials must reference a Secrets Manager secret ARN."
  }
}

variable "executor_image" {
  description = "Qualified Linux worker image by immutable digest; it must contain sh and tar, and no application keys or settings."
  type        = string
  default     = ""
}

variable "executor_namespace" {
  description = "Dedicated worker-only namespace with enforced restricted Pod Security and deny-all networking."
  type        = string
  default     = "lightwork-execution"
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.executor_namespace)) && !contains(["default", "kube-system"], var.executor_namespace)
    error_message = "Use a dedicated execution namespace, not default or kube-system."
  }
}
