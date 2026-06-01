output "alb_dns_name" {
  description = "ALB DNS name - access the platform here"
  value       = aws_lb.main.dns_name
}

output "ecr_api_url" {
  description = "ECR repository URL for API image"
  value       = aws_ecr_repository.api.repository_url
}

output "ecr_ui_url" {
  description = "ECR repository URL for UI image"
  value       = aws_ecr_repository.ui.repository_url
}

output "rds_endpoint" {
  description = "RDS cluster endpoint"
  value       = aws_rds_cluster.main.endpoint
}

output "redis_endpoint" {
  description = "ElastiCache endpoint"
  value       = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "deploy_commands" {
  description = "Commands to deploy after terraform apply"
  value       = <<-EOT
    # 1. Login to ECR
    aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${aws_ecr_repository.api.repository_url}

    # 2. Build and push API image
    docker build -t ${aws_ecr_repository.api.repository_url}:latest -f api/Dockerfile .
    docker push ${aws_ecr_repository.api.repository_url}:latest

    # 3. Build and push UI image
    docker build -t ${aws_ecr_repository.ui.repository_url}:latest -f ui/Dockerfile ui/
    docker push ${aws_ecr_repository.ui.repository_url}:latest

    # 4. Force new deployment
    aws ecs update-service --cluster ${aws_ecs_cluster.main.name} --service ${var.project_name}-api --force-new-deployment
    aws ecs update-service --cluster ${aws_ecs_cluster.main.name} --service ${var.project_name}-worker --force-new-deployment
    aws ecs update-service --cluster ${aws_ecs_cluster.main.name} --service ${var.project_name}-ui --force-new-deployment

    # 5. Access platform
    echo "Platform URL: http://${aws_lb.main.dns_name}"
  EOT
}
