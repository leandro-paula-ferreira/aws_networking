variable "vpc_name" {
  description = "Nome da VPC"
  type        = string
}

variable "enable_dns_support" {
  description = "Habilita suporte a DNS na VPC"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Habilita hostnames DNS para instâncias com IPs públicos na VPC"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "Bloco CIDR para a VPC"
  type        = string
}

variable "internet_gateway_name" {
  description = "Nome do internet gateway"
  type        = string
}

variable "nat_gateway_name" {
  description = "Nome do NAT gateway"
  type        = string
}

variable "public_route_table_name" {
  description = "Nome da tabela de rotas pública"
  type        = string
}

variable "private_route_table_name" {
  description = "Nome da tabela de rotas privada"
  type        = string
}

variable "eip_name" {
  description = "Nome do IP elástico para o NAT gateway"
  type        = string
}

variable "public_subnets" {
  description = "Lista de configurações de subnets públicas"
  type = list(object({
    name                    = string
    map_public_ip_on_launch = bool
    availability_zone       = string
    cidr_block              = string
  }))
}

variable "private_subnets" {
  description = "Lista de configurações de subnets privadas"
  type = list(object({
    name                    = string
    map_public_ip_on_launch = bool
    availability_zone       = string
    cidr_block              = string
  }))
}

variable "tags" {
  description = "Tags dos recursos"
  type        = map(string)
  default     = {}
}

variable "flow_logs_retention_days" {
  description = "Número de dias para reter logs de fluxo da VPC no CloudWatch"
  type        = number
  default     = 14
}

