# Configuração de logs de fluxo para a VPC
resource "aws_flow_log" "this" {
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.this.id
  iam_role_arn         = aws_iam_role.flow_logs.arn

  tags = merge(
    var.tags,
    {
      Name = "${var.vpc_name}-flow-logs"
    }
  )
}

# Chave KMS para criptografar os logs do CloudWatch
resource "aws_kms_key" "flow_logs" {
  description             = "KMS key para criptografia dos logs de fluxo da VPC ${var.vpc_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_flow_logs.json

  tags = merge(
    var.tags,
    {
      Name = "${var.vpc_name}-flow-logs-kms-key"
    }
  )
}

# Política da chave KMS para os flow logs
data "aws_iam_policy_document" "kms_flow_logs" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/vpc/flow-logs/${var.vpc_name}"]
    }
  }
}

# Data source para obter a região atual
data "aws_region" "current" {}

# Data source para obter o ID da conta atual
data "aws_caller_identity" "current" {}

# Alias para a chave KMS para facilitar identificação
resource "aws_kms_alias" "flow_logs" {
  name          = "alias/${var.vpc_name}-flow-logs-key"
  target_key_id = aws_kms_key.flow_logs.key_id
}

# Grupo de logs do CloudWatch com criptografia habilitada
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.vpc_name}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn # Habilitando criptografia com CMK

  tags = merge(
    var.tags,
    {
      Name = "${var.vpc_name}-flow-logs-group"
    }
  )
}
