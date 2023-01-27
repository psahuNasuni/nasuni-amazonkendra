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

resource "aws_iam_policy" "kendra_data_load" {
  name        = "${local.resource_name_prefix}-data_load_policy-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for data loading to Kendra"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "kendra:BatchPutDocument",
                "kendra:BatchDeleteDocument"
            ],
            "Resource": "*"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-data_load_policy-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "kendra_data_load_attachment" {
  role       = aws_iam_role.kendra_exec_role.name
  policy_arn = aws_iam_policy.kendra_data_load.arn
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
    command = "sh kendra_launch.sh ${random_id.kendra_unique_id.hex} ${var.region} ${var.aws_profile} ${aws_iam_role.kendra_exec_role.arn} ${data.aws_secretsmanager_secret_version.admin_secret_kendra.id}"
  }
   provisioner "local-exec" {
    when    = destroy
    command = "sh kendra_destroy.sh "
  }
  depends_on = [
    aws_iam_role.kendra_exec_role
  ]
}

