########################################################
##  Project       :   Nasuni Kendra Integration
##  Organization  :   Nasuni Labs   
#########################################################

data "aws_secretsmanager_secret" "user_secrets" {
  name = var.user_secret
}
data "aws_secretsmanager_secret_version" "current_user_secrets" {
  secret_id = data.aws_secretsmanager_secret.user_secrets.id
}   
 locals { 
  lambda_code_file_name_without_extension = "nac-kendra-metadata"
  lambda_code_extension                   = ".py"
  handler                                 = "lambda_handler"
  resource_name_prefix                    = "nasuni-labs"
  # nac_scheduler_name                      = jsondecode(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string)["nac_scheduler_name"]
  # nac_scheduler_name                 = jyessondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["nac_scheduler_name"]
  nac_scheduler_name                 = "nac_scheduler_1"
  nac_destination_bucket                  = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["destination_bucket"]
  # nac_source_bucket                       = jsondecode(nonsensitive(data.aws_secretsmanager_secret_version.current_user_secrets.secret_string))["source_bucket"]
}




data "aws_secretsmanager_secret" "scheduler_secrets" {
  name = var.internal_secret
}
data "aws_secretsmanager_secret_version" "current_scheduler_secrets" {
  secret_id = data.aws_secretsmanager_secret.scheduler_secrets.id
}   


data "aws_caller_identity" "current" {}

################### START - NAC Discovery Lambda ####################################################
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "nac-kendra-metadata/"
  output_path = "${local.lambda_code_file_name_without_extension}.zip"
}

resource "aws_lambda_function" "lambda_function" {
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "${local.lambda_code_file_name_without_extension}.${local.handler}"
  runtime          = var.runtime
  filename         = "${local.lambda_code_file_name_without_extension}.zip"
  function_name    = "${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-Lambda-${random_id.kendra_unique_id.hex}"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 20

  tags = {
    Name            = "${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-Lambda-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Elasticsearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
  depends_on = [
    aws_iam_role_policy_attachment.lambda_logging,
    aws_iam_role_policy_attachment.s3_GetObject_access,
    aws_iam_role_policy_attachment.GetSecretValue_access,
    aws_cloudwatch_log_group.lambda_log_group,
  ]
  environment {
    variables = {
      UserSecret = "${var.user_secret}",
      IntegrationID = "${random_id.kendra_unique_id.hex}",
      RoleARN = "${aws_iam_policy.s3_GetObject_access.arn}",
      AdminSecret = "${var.admin_secret}"
      SchedulerSecret = "${var.internal_secret}"
    }
  }

}

resource "aws_iam_role" "lambda_exec_role" {
  name        = "${local.resource_name_prefix}-lambda_exec_role-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "Allows Kendra Function to call AWS services on your behalf."

  assume_role_policy = jsonencode(
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
  )

  tags = {
    Name            = "${local.resource_name_prefix}-kendra_exec-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}


############## CloudWatch Integration for Lambda ######################
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${local.resource_name_prefix}-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
  retention_in_days = 14

  tags = {
    Name            = "${local.resource_name_prefix}-lambda_log_group-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

# AWS Lambda Basic Execution Role
resource "aws_iam_policy" "lambda_logging" {
  name        = "${local.resource_name_prefix}-lambda_logging_policy-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-lambda_logging_policy-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

############## IAM policy for accessing S3 from a lambda ######################
resource "aws_iam_policy" "s3_GetObject_access" {
  name        = "${local.resource_name_prefix}-s3_GetObject_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for accessing S3 from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::*"
        }
    ]
}
EOF
  tags = {
    Name            = "${local.resource_name_prefix}-s3_GetObject_access_policy-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }

}

resource "aws_iam_role_policy_attachment" "s3_GetObject_access" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.s3_GetObject_access.arn
}


############## IAM policy for accessing Secret Manager from a lambda ######################
resource "aws_iam_policy" "GetSecretValue_access" {
  name        = "GetSecretValue_access_policy-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for accessing secretmanager from a lambda"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "${data.aws_secretsmanager_secret.user_secrets.arn}"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "${data.aws_secretsmanager_secret.internal_secret.arn}"
        }
    ]
}
EOF
  tags = {
    Name            = "GetSecretValue_access_policy"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "GetSecretValue_access" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.GetSecretValue_access.arn
}


############## Kendra Role ######################

resource "aws_iam_role" "kendra_exec_role" {
  name        = "${local.resource_name_prefix}-kendra_exec_role-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
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
    Name            = "${local.resource_name_prefix}-kendra_exec-${local.lambda_code_file_name_without_extension}-${random_id.kendra_unique_id.hex}"
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


resource "aws_iam_policy" "NAC_Kendra_CloudWatch" {
  name        = "NAC_Kendra_CloudWatch_access_policy-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for enabling Kendra to access CloudWatch Logs"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "cloudwatch:namespace": "AWS/Kendra"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kendra/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogStreams",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kendra/*:log-stream:*"
            ]
        }
    ]
}
EOF
  tags = {
    Name            = "NAC_Kendra_CloudWatch_access_policy"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}


resource "aws_iam_role_policy_attachment" "NAC_Kendra_CloudWatch_Attachment" {
  role       = aws_iam_role.kendra_exec_role.name
  policy_arn = aws_iam_policy.NAC_Kendra_CloudWatch.arn
}



############## IAM policy for enabling Kendra to access and index S3 ######################
resource "aws_iam_policy" "KendraAccessS3" {
  name        = "KendraAccessS3_access_policy-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for enabling Kendra to access and index S3"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::${local.nac_destination_bucket}/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::${local.nac_destination_bucket}/*"
            ],
            "Effect": "Allow"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kendra:BatchPutDocument",
                "kendra:BatchDeleteDocument"
            ],
            "Resource": "arn:aws:kendra:${var.region}:${data.aws_caller_identity.current.account_id}:index/*"
        }
    ]
}
EOF
  tags = {
    Name            = "KendraAccessS3_access_policy"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "KendraAccessS3_Attachment" {
  role       = aws_iam_role.kendra_exec_role.name
  policy_arn = aws_iam_policy.KendraAccessS3.arn
}

data "aws_s3_bucket" "nac_destination_bucket"{
  bucket = local.nac_destination_bucket
}
################# Trigger Lambda Function on S3 Event ######################
resource "aws_lambda_permission" "allow_bucket" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.arn
  principal     = "s3.amazonaws.com"
  source_arn    = data.aws_s3_bucket.nac_destination_bucket.arn

  depends_on = [aws_lambda_function.lambda_function]
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = data.aws_s3_bucket.nac_destination_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.lambda_function.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "/nasuni-labs/${var.volume_name}/"
    filter_suffix       = ""
  }
  depends_on = [aws_lambda_permission.allow_bucket]
}

########################################## Internal Secret  ########################################################

data "aws_secretsmanager_secret" "internal_secret" {
  name = var.internal_secret
}
data "aws_secretsmanager_secret_version" "internal_secret" {
  secret_id = data.aws_secretsmanager_secret.internal_secret.id
}

# resource "aws_secretsmanager_secret" "internal_secret" {
#   name        = "nasuni-labs-internal-Kendra-${random_id.kendra_unique_id.hex}"
#   description = "Nasuni Analytics Connector's version specific internal secret. This will be created as well as destroyed along with NAC."
# }
# resource "aws_secretsmanager_secret_version" "internal_secret" {
#   secret_id     = aws_secretsmanager_secret.internal_secret.id
#   secret_string = jsonencode(local.secret_data_to_update)
#   depends_on = [
#     aws_iam_role.lambda_exec_role,
#     aws_lambda_function.lambda_function,
#   ]
# }


############## IAM policy for enabling Custom Document Enrichment on Kendra ######################
resource "aws_iam_policy" "KendraEnrichment" {
  name        = "KendraCustomDocumentEnrichment_policy-${random_id.kendra_unique_id.hex}"
  path        = "/"
  description = "IAM policy for enabling Custom Document Enrichment in Kendra"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": [
      "arn:aws:s3:::*/*"
    ],
    "Effect": "Allow"
  },
  {
    "Action": [
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::*"
    ],
    "Effect": "Allow"
  },
  {
    "Effect": "Allow",
    "Action": [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ],
    "Resource": [
      "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/*"
    ]
  },
  {
    "Effect": "Allow",
    "Action": [
      "lambda:InvokeFunction"
    ],
    "Resource": "arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:*"
  }]
}
EOF
  tags = {
    Name            = "KendraCustomDocumentEnrichment_policy"
    Application     = "Nasuni Analytics Connector with Kendra"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

resource "aws_iam_role_policy_attachment" "KendraEnrichment" {
  role       = aws_iam_role.kendra_exec_role.name
  policy_arn = aws_iam_policy.KendraEnrichment.arn
}


################################### Attaching AWS Managed IAM Policies ##############################################################

data "aws_iam_policy" "CloudWatchFullAccess" {
  arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

resource "aws_iam_role_policy_attachment" "CloudWatchFullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.CloudWatchFullAccess.arn
}

data "aws_iam_policy" "AWSCloudFormationFullAccess" {
  arn = "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess"
}

resource "aws_iam_role_policy_attachment" "AWSCloudFormationFullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AWSCloudFormationFullAccess.arn
}

data "aws_iam_policy" "AmazonS3FullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "AmazonS3FullAccess" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = data.aws_iam_policy.AmazonS3FullAccess.arn
}


resource "null_resource" "kendra_launch" {
  provisioner "local-exec" {
    command = "pip install boto3==1.0.0"
  }
  provisioner "local-exec" {
    command = "python3 kendra_launch.py ${var.admin_secret} ${random_id.kendra_unique_id.hex} ${var.region} ${data.aws_secretsmanager_secret_version.current_scheduler_secrets.secret_id}"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "python3 kendra_destroy.py"
  }
    depends_on = [aws_iam_role.kendra_exec_role,
                  data.aws_secretsmanager_secret_version.current_scheduler_secrets]
    # depends_on = [aws_iam_role.kendra_exec_role]

}

resource "random_id" "kendra_unique_id" {
  byte_length = 3
}






