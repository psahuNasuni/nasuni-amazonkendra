#!/bin/bash

# ./kendra_destroy.sh ${random_id.kendra_unique_id.hex} ${var.region} ${var.aws_profile} ${aws_iam_role.kendra_exec_role.arn}"
KENDRA_UNIQUE_ID=$1
AWS_REGION=$2
AWS_PROFILE=$3
KENDRA_EXEC_ROLE_ARN=$4

echo "INFO ::: Started - Destroying Kendra Service !!!"