########################################################
##  Project       :   Nasuni Kendra Integration
##  Organization  :   Nasuni Labs   
#########################################################

data "aws_secretsmanager_secret" "kendra_admin_secret" {
  name = var.kendra_admin_secret
}
data "aws_secretsmanager_secret_version" "kendra_admin_secret" {
  secret_id = data.aws_secretsmanager_secret.kendra_admin_secret.id
}   
 locals { 
  resource_name_prefix                    = "nasuni-labs-kendra"
}

data "aws_caller_identity" "current" {}


resource "random_id" "kendra_unique_id" {
  byte_length = 3
}


############## Kendra Role ######################

resource "aws_iam_role" "kendra_exec_role" {
  name        = "${local.resource_name_prefix}-exec_role-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "Allows Kendra Function to call AWS services on your behalf."

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",  
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "kendra.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    Name            = "${local.resource_name_prefix}-exec_role-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}


############## IAM policy for enabling Kendra to access CloudWatch Logs ######################
data "aws_iam_policy_document" "kendra-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["kendra.amazonaws.com"]
    }
  }
}


resource "null_resource" "kendra_launch" {
   provisioner "local-exec" {
    command = "sh kendra_launch.sh"
  }
   provisioner "local-exec" {
    when    = destroy
    command = "sh kendra_destroy.sh"
  }
}

