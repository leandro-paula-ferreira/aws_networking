resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    var.tags,
    {
      Name = var.private_route_table_name
    }
  )
}

resource "aws_route" "private_nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnets)

  subnet_id      = aws_subnet.privates[count.index].id
  route_table_id = aws_route_table.private.id
}
