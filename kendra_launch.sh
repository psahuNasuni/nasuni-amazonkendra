#!/bin/bash

# ./kendra_launch.sh ${random_id.kendra_unique_id.hex} ${var.region} ${var.aws_profile} ${aws_iam_role.kendra_exec_role.arn}"
KENDRA_UNIQUE_ID=$1
AWS_REGION=$2
AWS_PROFILE=$3
ROLE_ARN=$4
KENDRA_ADMIN_SECRET=$5

KENDRA_NAME="nasuni-labs-kendra"-$KENDRA_UNIQUE_ID
echo "INFO ::: Started - Provisioning Kendra Service !!!"

echo "INFO :::  KENDRA_NAME:$KENDRA_NAME"

echo "INFO ::: Launching kendra Index"

sleep 30
KENDRA_ID=$(aws kendra create-index --edition DEVELOPER_EDITION --name ${KENDRA_NAME} --profile ${AWS_PROFILE} --role-arn ${ROLE_ARN}| jq '.[]'| tr -d '"' )
echo "INFO ::: Kendra_Id :: " $KENDRA_ID
echo "INFO ::: Creating kendra "
KENDRA_INDEX_STATUS=$(aws kendra describe-index --id "${KENDRA_ID}" --profile $AWS_PROFILE --region $AWS_REGION | jq -r .Status)
echo "INFO ::: KENDRA_INDEX_STATUS " $KENDRA_INDEX_STATUS
# sleep 700

while [ "$KENDRA_INDEX_STATUS" != "ACTIVE" ]; do
    if [ "$KENDRA_INDEX_STATUS" == "FAILED" ]; then
        echo "ERROR ::: Kendra Index creation FAILED . . . . . . . . . . "
        # sh launch_kendra.sh
    elif [ "$KENDRA_INDEX_STATUS" == "" ]; then
        echo "INFO ::: KENDRA_INDEX_STATUS " $KENDRA_INDEX_STATUS
        echo "Status is blank"
        sleep 120
    elif [ "$KENDRA_INDEX_STATUS" == "CREATING" ]; then
        echo "INFO ::: KENDRA_INDEX_STATUS " $KENDRA_INDEX_STATUS

    fi
    KENDRA_INDEX_STATUS=$(aws kendra describe-index --id "${KENDRA_ID}" --profile $AWS_PROFILE --region $AWS_REGION | jq -r .Status)
done    
RES="$?"
if [ $RES -ne 0 ]; then
    echo "ERROR ::: $RES Failed to Create kendra $KENDRA_NAME as, its already exists."
    exit 1
elif [ $RES -eq 0 ]; then
    echo "INFO ::: kendra $KENDRA_NAME Created"
fi
aws secretsmanager put-secret-value --secret-id "${KENDRA_ADMIN_SECRET}" --secret-string "{\"index_id\":\"$KENDRA_ID\",\"index_name\":\"$KENDRA_NAME\"}" --profile nasuni
RES="$?"
if [ $RES -ne 0 ]; then
    echo "ERROR ::: $RES Failed to update Secret $KENDRA_ADMIN_SECRET as, its already exists."
    exit 1
elif [ $RES -eq 0 ]; then
    echo "INFO ::: $KENDRA_ADMIN_SECRET secret updated successfully"
fi
