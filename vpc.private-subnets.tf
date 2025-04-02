resource "aws_subnet" "privates" {
  count = length(var.private_subnets)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.private_subnets[count.index].cidr_block
  availability_zone       = var.private_subnets[count.index].availability_zone
  map_public_ip_on_launch = false

  tags = merge(
    var.tags,
    {
      Name                                           = var.private_subnets[count.index].name
      "kubernetes.io/role/internal-elb"              = 1
      "kubernetes.io/cluster/${var.tags["Project"]}" = "shared"
    }
  )
}
