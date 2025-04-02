output "vpc_id" {
  value       = aws_vpc.this.id
  description = "O ID da VPC"
}

output "vpc_arn" {
  value       = aws_vpc.this.arn
  description = "O ARN da VPC"
}

output "vpc_cidr_block" {
  value       = aws_vpc.this.cidr_block
  description = "O bloco CIDR da VPC"
}

output "public_subnet_ids" {
  value       = aws_subnet.publics[*].id
  description = "Lista de IDs das subnets públicas"
}

output "private_subnet_ids" {
  value       = aws_subnet.privates[*].id
  description = "Lista de IDs das subnets privadas"
}

output "public_subnet_arns" {
  value       = aws_subnet.publics[*].arn
  description = "Lista de ARNs das subnets públicas"
}

output "private_subnet_arns" {
  value       = aws_subnet.privates[*].arn
  description = "Lista de ARNs das subnets privadas"
}

output "nat_gateway_id" {
  value       = aws_nat_gateway.this.id
  description = "O ID do NAT Gateway"
}

output "internet_gateway_id" {
  value       = aws_internet_gateway.this.id
  description = "O ID do Internet Gateway"
}

output "vpc_flow_log_id" {
  value       = aws_flow_log.this.id
  description = "O ID do recurso de Flow Log da VPC"
}

output "vpc_flow_log_log_group_arn" {
  value       = aws_cloudwatch_log_group.flow_logs.arn
  description = "O ARN do grupo de logs do CloudWatch para Flow Logs da VPC"
}
