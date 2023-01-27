#!/bin/bash

# ./kendra_launch.sh ${random_id.kendra_unique_id.hex} ${var.region} ${var.aws_profile} ${aws_iam_role.kendra_exec_role.arn}"
KENDRA_UNIQUE_ID=$1
AWS_REGION=$2
AWS_PROFILE=$3
KENDRA_EXEC_ROLE_ARN=$4

echo "INFO ::: Started - Provisioning Kendra Service !!!"
cat "$KENDRA_EXEC_ROLE_ARN 465577867787878" > a.txt