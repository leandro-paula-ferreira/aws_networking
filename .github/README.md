# Documentação do Projeto ColabKids

![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/github%20actions-%232671E5.svg?style=for-the-badge&logo=githubactions&logoColor=white)

## Visão Geral

Este projeto Terraform implementa a infraestrutura para a aplicação ColabKids na AWS, seguindo as melhores práticas de segurança recomendadas pelo tfsec. A infraestrutura inclui:

- VPC com subnets públicas e privadas
- Cluster EKS para Kubernetes
- Repositórios ECR para imagens de contêiner
- Configuração de DNS usando Route53
- Certificado SSL/TLS gerenciado pelo ACM
- Integração com GitHub Actions para CI/CD

## Estrutura do Projeto

```
colabkids-terraform-aws/
├── .github/
│   ├── README.md            # Documentação dos workflows
│   └── workflows/
│       ├── terraform-pr-checks.yml
│       ├── terraform-plan.yml
│       └── terraform-apply.yml
├── infra/
│   ├── main.tf                # Arquivo principal que integra todos os módulos
│   ├── variables.tf           # Declaração de variáveis para o projeto
│   ├── outputs.tf             # Outputs do projeto
│   ├── provider.tf            # Configuração do provider Terraform e backend S3
│   ├── bootstrap/             # Scripts para configuração inicial do backend S3
│   └── modules/
│       ├── dns/               # Gerenciamento de DNS e certificados
│       ├── ecr/               # Repositórios de contêineres
│       ├── eks/               # Cluster Kubernetes
│       ├── iam/               # Gerenciamento de identidade e acesso
│       └── networking/        # Configuração de rede
└── README.md                  # Documentação principal do projeto
```

## Módulos

### Networking

Responsável pela criação da VPC, subnets, gateways e tabelas de roteamento.

**Recursos principais:**
- VPC com CIDR 10.0.0.0/24
- Subnets públicas em múltiplas zonas de disponibilidade
- Subnets privadas em múltiplas zonas de disponibilidade
- Internet Gateway para tráfego de saída
- NAT Gateway para subnets privadas
- Tabelas de roteamento configuradas adequadamente
- VPC Flow Logs habilitados para auditoria de tráfego

### EKS

Configura um cluster Kubernetes gerenciado com segurança aprimorada.

**Recursos principais:**
- Cluster EKS com logs habilitados
- Grupo de nós gerenciado com instâncias t3.medium
- Configuração de IAM para acesso ao cluster
- Criptografia de secrets do Kubernetes
- Provedor OIDC para autenticação
- Configuração de segurança para nós (IMDSv2, discos criptografados)

### ECR

Cria repositórios para armazenar imagens de contêiner.

**Recursos principais:**
- Repositórios para frontend e backend
- Escaneamento de vulnerabilidades em imagens
- Criptografia de imagens com chaves KMS gerenciadas pelo cliente
- Política de ciclo de vida para gerenciamento de imagens antigas
- Tags imutáveis para maior segurança

### DNS

Gerencia a configuração de domínio e certificados SSL/TLS.

**Recursos principais:**
- Zona hospedada no Route53
- Certificado ACM para leandrospferreira.com.br
- Validação automática de certificado por DNS
- Logging de transparência de certificado

### IAM

Configura permissões e integração com GitHub Actions.

**Recursos principais:**
- Provedor OIDC para GitHub Actions
- Role IAM com permissões mínimas necessárias
- Políticas específicas para acesso a repositórios ECR

## CI/CD com GitHub Actions

O projeto utiliza GitHub Actions para automatizar a validação, planejamento e aplicação da infraestrutura Terraform.

### Workflows Disponíveis

#### 1. Terraform PR Checks
Executa verificações rápidas de qualidade de código e segurança quando um PR é aberto:
- Format: Verifica a formatação do código
- Lint: Identifica problemas com TFLint
- Validate: Verifica a sintaxe e configuração
- Security: Executa análise de segurança com tfsec e Checkov

#### 2. Terraform Plan
Gera um plano do Terraform para revisão quando um PR é aberto:
- Inicializa o Terraform
- Gera um plano de execução
- Publica o plano como comentário no PR
- Salva o plano como artefato

#### 3. Terraform Apply
Aplica as mudanças após a aprovação e merge do PR:
- Inicializa o Terraform
- Gera um plano final
- Aplica o plano
- Captura e salva os outputs

Para mais detalhes sobre os workflows, consulte a [documentação de CI/CD](.github/README.md).

## Segurança e Boas Práticas

Este projeto implementa várias melhorias de segurança recomendadas pelo tfsec:

1. **EKS**:
   - Criptografia de secrets do Kubernetes
   - Implementação de IMDSv2 para proteção de metadados da instância
   - Volumes EBS criptografados para nós
   - Controle granular de acesso com roles IAM específicas
   - Restrição de acesso público ao endpoint do cluster

2. **ECR**:
   - Escaneamento automático de vulnerabilidades
   - Criptografia de imagens com chaves KMS gerenciadas pelo cliente
   - Tags imutáveis para prevenir substituição de imagens
   - Política de ciclo de vida para gerenciar imagens antigas

3. **IAM**:
   - Princípio de privilégio mínimo
   - Restrição de repositórios GitHub que podem assumir roles
   - Descrições detalhadas para facilitar auditoria

4. **Rede**:
   - Subnets privadas para recursos que não precisam de acesso público direto
   - Configuração adequada de tabelas de roteamento
   - VPC Flow Logs habilitados para monitoramento de tráfego
   - Tags para integração com Kubernetes

5. **TLS/SSL**:
   - Logging de transparência de certificado
   - Validação automática de certificados

## Como Usar

### Pré-requisitos

- Terraform >= 1.0.0
- AWS CLI configurado
- Permissão para assumir a role de Terraform (arn:aws:iam::VALOR:role/terraform-role)

### Configuração Inicial do Backend

Antes de aplicar a infraestrutura principal, configure o backend S3:

```bash
cd infra/bootstrap
terraform init
terraform apply
```

### Aplicando a Infraestrutura

```bash
cd infra
terraform init \
  -backend-config="role_arn=arn:aws:iam::VALOR:role/terraform-role" \
  -backend-config="external_id=VALOR"

terraform plan -out=plan.tfplan
terraform apply plan.tfplan
```

### Desenvolvimento com CI/CD

1. Clone o repositório:
   ```bash
   git clone https://github.com/leandro-paula-ferreira/colabkids-terraform-aws.git
   cd colabkids-terraform-aws
   ```

2. Crie uma branch para suas alterações:
   ```bash
   git checkout -b feature/nova-funcionalidade
   ```

3. Faça as alterações necessárias na infraestrutura

4. Envie para o repositório remoto e crie um Pull Request:
   ```bash
   git add .
   git commit -m "Adiciona nova funcionalidade"
   git push origin feature/nova-funcionalidade
   ```

5. Os workflows do GitHub Actions executarão automaticamente as verificações e gerarão um plano para revisão

6. Após a aprovação e merge do PR, o workflow de Apply aplicará as mudanças automaticamente

### Configurando o Acesso ao Cluster EKS

Após a criação do cluster, configure o kubectl:

```bash
aws eks update-kubeconfig --name colabkids-eks-cluster --region us-east-1 \
  --role-arn arn:aws:iam::VALOR:role/terraform-role
```

## Variáveis de Entrada

| Nome | Descrição | Tipo | Valor Padrão |
|------|-----------|------|--------------|
| region | Região AWS para deploy dos recursos | string | us-east-1 |
| tags | Tags a serem aplicadas em todos os recursos | map(string) | {Environment = "production", Project = "colabkids"} |
| vpc | Configuração da rede VPC | object | Ver variables.tf |
| eks_cluster | Configuração do cluster EKS | object | Ver variables.tf |
| ecr_repositories | Lista de repositórios ECR | list(object) | frontend e backend |
| route53 | Configurações de DNS | object | {domain_name = "leandrospferreira.com.br"} |

## Outputs

| Nome | Descrição |
|------|-----------|
| vpc_id | ID da VPC |
| public_subnet_ids | IDs das subnets públicas |
| private_subnet_ids | IDs das subnets privadas |
| ecr_repository_urls | URLs dos repositórios ECR |
| eks_cluster_name | Nome do cluster EKS |
| eks_cluster_endpoint | Endpoint do cluster EKS |
| eks_oidc_provider_arn | ARN do provedor OIDC do EKS |
| github_role_arn | ARN da role para GitHub Actions |
| route53_zone_id | ID da zona do Route53 |
| route53_nameservers | Nameservers do domínio |
| acm_certificate_arn | ARN do certificado ACM |

## Manutenção e Troubleshooting

### Rotação de Credenciais

As chaves KMS utilizadas para criptografia são configuradas com rotação automática.

### Logs e Monitoramento

- O cluster EKS está configurado para enviar logs para o CloudWatch
- VPC Flow Logs estão habilitados para monitoramento de tráfego
- Os repositórios ECR têm escaneamento automático de vulnerabilidades

### Solução de Problemas Comuns

1. **Erro de acesso negado ao assumir role**: Verifique se o usuário tem permissão para assumir a role especificada e se o external_id está correto.

2. **Erro de inicialização do backend S3**: Use o comando terraform init com os parâmetros de backend-config.

3. **Falha na validação do certificado ACM**: Pode levar até 30 minutos para concluir a validação DNS. Verifique se os registros DNS foram criados corretamente.

4. **Falhas em workflows do GitHub Actions**: Verifique se todos os secrets necessários estão configurados corretamente no repositório.

## Contribuição

Para contribuir com este projeto:

1. Crie um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Faça commit das suas alterações (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

Todas as contribuições passarão pelos workflows de CI/CD automatizados para garantir a qualidade e segurança do código.




# Terraform CI/CD Pipeline

Este repositório contém workflows do GitHub Actions para automatizar a execução de Terraform em um ambiente AWS. Os workflows incluem:

- **`terraform-apply.yml`**: Aplica as mudanças de infraestrutura.
- **`terraform-plan.yml`**: Gera e compartilha o plano de mudanças do Terraform.
- **`terraform-pr-checks.yml`**: Validação e verificação de segurança do Terraform.

## Estrutura dos Workflows

### **1. `terraform-apply.yml`** (Aplicar Infraestrutura)
Este workflow é acionado sempre que um commit é feito na branch `main`. Ele executa:

- Inicialização do Terraform.
- Configuração das credenciais AWS.
- Execução do `terraform plan` para visualizar mudanças.
- Execução do `terraform apply` para aplicar as mudanças automaticamente.
- Armazena os outputs do Terraform como artefatos para referência futura.

### **2. `terraform-plan.yml`** (Gerar Plano de Mudanças)
Este workflow é acionado quando um Pull Request é aberto contra `main`.

- Executa `terraform plan` e salva o resultado.
- Publica o plano nos artefatos do GitHub Actions.
- Comenta o plano no PR para revisão fácil.

### **3. `terraform-pr-checks.yml`** (Validação e Análise de Segurança)
Executa checagens de qualidade de código e segurança no Terraform antes de aprovar um PR:

- `terraform fmt`: Verifica formatação.
- `tflint`: Analisa possíveis erros e melhores práticas.
- `terraform validate`: Verifica sintaxe e erros gerais.
- `tfsec` e `checkov`: Realizam análises de segurança na infraestrutura.

## **Como Utilizar**
1. Clone o repositório:
   ```sh
   git clone https://github.com/seu-usuario/seu-repositorio.git
   cd seu-repositorio
   ```
2. Configure os segredos no GitHub (Settings > Secrets and Variables > Actions):
   - `TF_API_TOKEN` (Token para autenticação no Terraform Cloud/Enterprise)
   - `AWS_ROLE_ARN` (Role assumida para autenticação na AWS)
   - `GITHUB_TOKEN` (Padrão do GitHub para interação com PRs)
3. Abra um Pull Request e veja o `terraform plan`.
4. Se tudo estiver correto, faça merge para `main` para aplicar as mudanças.

## **Contribuição**
- Crie uma branch para sua feature: `git checkout -b feature-nova`
- Faça commit das mudanças: `git commit -m "Minha alteração"`
- Suba a branch para o repositório: `git push origin feature-nova`
- Abra um Pull Request para `main`.

## **Licença**
Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

