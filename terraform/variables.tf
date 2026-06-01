variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "prowler-cnapp"
}

variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "ap-southeast-1"
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "domain_name" {
  description = "Domain name for ACM certificate (e.g., prowler.example.com)"
  type        = string
  default     = "prowler.example.com"
}

variable "tags" {
  description = "Tags for all resources"
  type        = map(string)
  default = {
    Project     = "prowler-cnapp"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

variable "org_id" {
  description = "AWS Organization ID for scoping permissions"
  type        = string
  default     = ""
}
