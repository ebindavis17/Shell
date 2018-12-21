import boto3
from botocore.exceptions import ClientError

pro = []

shieldpro = boto3.client('shield','us-east-1')

try:
   protected = shieldpro.list_protections(MaxResults=100)

   for i in protected['Protections']:
       pro.append(i['ResourceArn'])
   print(pro)

except ClientError as e:
       if e.response['Error']['Code'] == 'ResourceNotFoundException':

           print("hey")
