# Demo Terraform (pattern-oriented)
# This is NOT intended for deployment. It's designed to trigger posture findings.

resource "aws_security_group" "demo_sg" {
  name = "demo-sg"
  egress = "0.0.0.0/0"
}

resource "aws_iam_policy" "demo_admin" {
  name   = "demo-admin"
  policy = "{ \"Statement\": [{ \"Action\": \"*\", \"Effect\": \"Allow\", \"Resource\": \"*\" }] }"
}

resource "aws_lambda_function" "demo_fn" {
  function_name = "demoFn"
  handler       = "index.handler"
  runtime       = "python3.11"
  role          = "aws_iam_role.lambda_exec.arn"
}

resource "aws_lambda_permission" "demo_invoke" {
  statement_id  = "AllowExecutionFromAnywhere"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.demo_fn.function_name
  principal     = "*"
}
