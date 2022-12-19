#! /usr/bin/python3

import boto3
from botocore.exceptions import ClientError
import pprint
import time
import hcl
import os

#Identify tfvars file
try:
    tfvars_file = [x for x in os.listdir('.') if '.tfvars' in x][0]
except  Exception as e:
        print("%s" % e)
        exit


#Load variables from kendra variables file
with open(tfvars_file, 'r') as fp: 
    obj = hcl.load(fp) 
    user_secret = obj['user_secret']
    aws_profile = obj['aws_profile']
    volume_name = obj['volume_name']


#Set up clients
session = boto3.Session(profile_name=aws_profile) 
kendra = session.client("kendra")
secretsmanager = session.client("secretsmanager")
account_id = session.client('sts').get_caller_identity().get('Account')

#Collect secretss

kwargs = {'SecretId': user_secret}
secret_response = secretsmanager.get_secret_value(**kwargs)
secrets = eval(secret_response['SecretString'])
index_id = secrets['kendra_index_id']
datasource_id = secrets['kendra_datasource_id']
#experience_id = secrets['kendra_experience_id']

#Destroy Kendra index

print("Destorying the index")

try:
    index_response = kendra.delete_index(
        Id = index_id)

    pprint.pprint(index_response)


    while True:
        # Get index description
        index_description = kendra.describe_index(
            Id = index_id
        )
        # When status is not CREATING quit.
        status = index_description["Status"]
        print("    Deleting index. Status: "+status)
        time.sleep(10)
        if status != "DELETING":
            break

except  ClientError as e:
        print("%s" % e)


#Experience Builder disabled for now while we troubleshoot issues with IAM

'''
print("Delete the experience")


try:
    experience_response = kendra.delete_experience(
        Id = experience_id,
        IndexId = index_id
    )

    pprint.pprint(experience_response)

    print("Wait for Kendra to delete the experience.")

    while True:
        # Get the experience description
        experience_description = kendra.describe_experience(
            Id = experience_id,
            IndexId = index_id
        )
        status = experience_description["Status"]
        print("    Deleting experience. Status: "+status)
        time.sleep(60)
        if status != "DELETING":
            break

except  ClientError as e:
        print("%s" % e)

'''

print("Program ends.")