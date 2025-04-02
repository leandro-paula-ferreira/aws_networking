
# Módulo Networking

Este módulo é responsável por criar a infraestrutura de rede na AWS.

## Recursos Criados

- VPC com CIDR personalizado
- Subnets públicas e privadas em múltiplas zonas de disponibilidade
- Internet Gateway para acesso à internet
- NAT Gateway para permitir que recursos nas subnets privadas acessem a internet
- Elastic IP para o NAT Gateway
- Tabelas de roteamento separadas para subnets públicas e privadas
- Associações de tabelas de roteamento

## Entradas (Variables)

| Nome | Descrição | Tipo | Obrigatório |
|------|-----------|------|------------|
| vpc_name | Nome da VPC | string | Sim |
| vpc_cidr | Bloco CIDR da VPC | string | Sim |
| internet_gateway_name | Nome do Internet Gateway | string | Sim |
| nat_gateway_name | Nome do NAT Gateway | string | Sim |
| public_route_table_name | Nome da tabela de rotas pública | string | Sim |
| private_route_table_name | Nome da tabela de rotas privada | string | Sim |
| eip_name | Nome do IP elástico para o NAT Gateway | string | Sim |
| public_subnets | Lista de configurações de subnets públicas | list(object) | Sim |
| private_subnets | Lista de configurações de subnets privadas | list(object) | Sim |
| tags | Tags dos recursos | map(string) | Não |

### Formato dos objetos de subnets

```hcl
public_subnets = [
  {
    name                    = "subnet-public-1a"
    map_public_ip_on_launch = true
    availability_zone       = "us-east-1a"
    cidr_block              = "10.0.0.0/26"
  }
]
```

## Saídas (Outputs)

| Nome | Descrição |
|------|-----------|
| vpc_id | O ID da VPC |
| vpc_arn | O ARN da VPC |
| vpc_cidr_block | O bloco CIDR da VPC |
| public_subnet_ids | Lista de IDs das subnets públicas |
| private_subnet_ids | Lista de IDs das subnets privadas |
| public_subnet_arns | Lista de ARNs das subnets públicas |
| private_subnet_arns | Lista de ARNs das subnets privadas |
| nat_gateway_id | O ID do NAT Gateway |
| internet_gateway_id | O ID do Internet Gateway |

## Exemplo de Uso

```hcl
module "networking" {
  source = "./modules/networking"

  vpc_name                 = "minha-vpc"
  vpc_cidr                 = "10.0.0.0/24"
  internet_gateway_name    = "minha-vpc-igw"
  nat_gateway_name         = "minha-vpc-nat"
  public_route_table_name  = "minha-vpc-public-rt"
  private_route_table_name = "minha-vpc-private-rt"
  eip_name                 = "minha-vpc-eip"
  
  public_subnets = [
    {
      name                    = "minha-vpc-public-subnet-us-east-1a"
      map_public_ip_on_launch = true
      availability_zone       = "us-east-1a"
      cidr_block              = "10.0.0.0/26"
    },
    {
      name                    = "minha-vpc-public-subnet-us-east-1b"
      map_public_ip_on_launch = true
      availability_zone       = "us-east-1b"
      cidr_block              = "10.0.0.64/26"
    }
  ]
  
  private_subnets = [
    {
      name                    = "minha-vpc-private-subnet-us-east-1a"
      map_public_ip_on_launch = false
      availability_zone       = "us-east-1a"
      cidr_block              = "10.0.0.128/26"
    },
    {
      name                    = "minha-vpc-private-subnet-us-east-1b"
      map_public_ip_on_launch = false
      availability_zone       = "us-east-1b"
      cidr_block              = "10.0.0.192/26"
    }
  ]
  
  tags = {
    Environment = "production"
    Project     = "meu-projeto"
  }
}
```

## Boas Práticas Implementadas

1. **Segmentação de Rede**: Separação entre subnets públicas e privadas para melhor isolamento de recursos.

2. **Alta Disponibilidade**: Recursos distribuídos em múltiplas zonas de disponibilidade.

3. **Princípio de Menor Privilégio**: Apenas recursos que precisam de acesso público estão nas subnets públicas.

4. **Integração com EKS**: As subnets incluem tags específicas para integração com o Kubernetes.

5. **Nomeação Consistente**: Padrão de nomenclatura claro para todos os recursos.

6. **Configuração de DNS**: Habilitação de DNS na VPC para resolução de nomes interna.

7. **Saída Controlada para Internet**: Tráfego das subnets privadas sai para internet através do NAT Gateway, não diretamente.

## Considerações de Segurança

- As subnets privadas não têm acesso direto da internet, protegendo recursos sensíveis.
- O acesso à internet das subnets privadas é feito através do NAT Gateway, permitindo atualizações e downloads.
- Recursos que não precisam de endereços IP públicos estão em subnets privadas.
- As tabelas de roteamento são configuradas para limitar o fluxo de tráfego conforme necessário.











## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_eip.nat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_internet_gateway.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/internet_gateway) | resource |
| [aws_nat_gateway.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/nat_gateway) | resource |
| [aws_route.private_nat_gateway](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route.public_internet_gateway](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route_table.private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table.public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table_association.private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_route_table_association.public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_subnet.privates](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_subnet.publics](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_vpc.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_eip_name"></a> [eip\_name](#input\_eip\_name) | Nome do IP elástico para o NAT gateway | `string` | n/a | yes |
| <a name="input_internet_gateway_name"></a> [internet\_gateway\_name](#input\_internet\_gateway\_name) | Nome do internet gateway | `string` | n/a | yes |
| <a name="input_nat_gateway_name"></a> [nat\_gateway\_name](#input\_nat\_gateway\_name) | Nome do NAT gateway | `string` | n/a | yes |
| <a name="input_private_route_table_name"></a> [private\_route\_table\_name](#input\_private\_route\_table\_name) | Nome da tabela de rotas privada | `string` | n/a | yes |
| <a name="input_private_subnets"></a> [private\_subnets](#input\_private\_subnets) | Lista de configurações de subnets privadas | <pre>list(object({<br/>    name                    = string<br/>    map_public_ip_on_launch = bool<br/>    availability_zone       = string<br/>    cidr_block              = string<br/>  }))</pre> | n/a | yes |
| <a name="input_public_route_table_name"></a> [public\_route\_table\_name](#input\_public\_route\_table\_name) | Nome da tabela de rotas pública | `string` | n/a | yes |
| <a name="input_public_subnets"></a> [public\_subnets](#input\_public\_subnets) | Lista de configurações de subnets públicas | <pre>list(object({<br/>    name                    = string<br/>    map_public_ip_on_launch = bool<br/>    availability_zone       = string<br/>    cidr_block              = string<br/>  }))</pre> | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags dos recursos | `map(string)` | `{}` | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | Bloco CIDR para a VPC | `string` | n/a | yes |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | Nome da VPC | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_internet_gateway_id"></a> [internet\_gateway\_id](#output\_internet\_gateway\_id) | O ID do Internet Gateway |
| <a name="output_nat_gateway_id"></a> [nat\_gateway\_id](#output\_nat\_gateway\_id) | O ID do NAT Gateway |
| <a name="output_private_subnet_arns"></a> [private\_subnet\_arns](#output\_private\_subnet\_arns) | Lista de ARNs das subnets privadas |
| <a name="output_private_subnet_ids"></a> [private\_subnet\_ids](#output\_private\_subnet\_ids) | Lista de IDs das subnets privadas |
| <a name="output_public_subnet_arns"></a> [public\_subnet\_arns](#output\_public\_subnet\_arns) | Lista de ARNs das subnets públicas |
| <a name="output_public_subnet_ids"></a> [public\_subnet\_ids](#output\_public\_subnet\_ids) | Lista de IDs das subnets públicas |
| <a name="output_vpc_arn"></a> [vpc\_arn](#output\_vpc\_arn) | O ARN da VPC |
| <a name="output_vpc_cidr_block"></a> [vpc\_cidr\_block](#output\_vpc\_cidr\_block) | O bloco CIDR da VPC |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | O ID da VPC |
