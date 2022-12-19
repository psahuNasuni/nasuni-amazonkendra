from ast import In
import json
import urllib.parse
import boto3
import os

print('Loading function')

#Clients
s3 = boto3.client('s3')
secrets_client = boto3.client("secretsmanager")
kendra = boto3.client('kendra')

#Environment Variables
IntegrationID = os.environ['IntegrationID']
UserSecret = os.environ['UserSecret']
RoleARN = os.enviorn['RoleARN']
AdminSecret = os.environ['admin_secret']


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')

    #Get secrets from the User Secret
    user_kwargs = {'SecretId': UserSecret}
    user_secret_response = secrets_client.get_secret_value(**user_kwargs)
    user_secret_dictionary = json.loads(user_secret_response['SecretString'])
    data_loc = key.find('data')

    #Get data from the Admin Secret
    admin_kwargs = {'SecretId': AdminSecret}
    admin_secret_response = secrets_client.get_secret_value(**admin_kwargs)
    admin_secret_dictionary = json.loads(admin_secret_response['SecretString'])
    kendra_index_id = admin_secret_dictionary[IntegrationID]['kendra_index_id']
    latest_toc = admin_secret_dictionary[IntegrationID]['latest_toc_handle_processed']

    #Create new source reference
    if 'directory_path' in user_secret_dictionary:
        source_url = user_secret_dictionary['directory_path']+key[data_loc+5:]
    elif 'web_access_appliance_address' in user_secret_dictionary:
        web_access_appliance_address = user_secret_dictionary['web_access_appliance_address']
        source_url = 'https://'+web_access_appliance_address+'/fs/view/'+key[data_loc+5:]
    else:
        pass

    #Create new id based on path and version
    doc_id = key + '_'+latest_toc

    try:
        #Upload object to Kendra

        put_doc_response = kendra.batch_put_document(
            IndexId=kendra_index_id,
            RoleArn=RoleARN,
            Documents=[
                {
                    'Id': doc_id,
                    'Title': key,
                    'S3Path': {
                        'Bucket': bucket,
                        'Key': key
                    },
                    'Attributes': [
                        {
                            'Key': '_source_uri',
                            'Value': {
                                'StringValue': source_url,
                            }
                        },
                    ]
                }
            ]
        )

        if "FailedDocuments" in put_doc_response:
            if put_doc_response["FailedDocuments"] != []:
                for failed_doc in put_doc_response["FailedDocuments"]:
                    print(failed_doc)
        else:
            print("Added document "+doc_id)
            #Delete the document from the bucket
            delete_response = s3.delete_object(Bucket=bucket, Key=key)
            print("Deleted "+key+" from "+bucket)
        return True
    except Exception as e:
        print(e)
        print('Error putting object {} in bucket {}.'.format(key, bucket))
        raise e
        
        
        