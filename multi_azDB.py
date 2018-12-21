import boto3

client = boto3.client('rds')

dbmultiAZ = []
finalbd = []
new = []

def lambda_handler(event,context):
    response1=client.describe_db_instances()
    
    for i in response1['DBInstances']:
        if i['DBInstanceStatus'] == 'available':
            
            if i['MultiAZ']==True:
                response2 = client.modify_db_instance(
                    DBInstanceIdentifier=i['DBInstanceIdentifier'],
                    ApplyImmediately=True,
                    MultiAZ=False
                    )
            
        
            else:
                if i['Engine'] != 'aurora':
                    response3 = client.stop_db_instance(
                        DBInstanceIdentifier=i['DBInstanceIdentifier'])