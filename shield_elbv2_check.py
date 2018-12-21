import boto3

elbv1 = []
elbv1ARN = []
elbv2 = []
pro = []

client = boto3.client('elbv2')
shieldpro = boto3.client('shield','us-east-1')


response = client.describe_load_balancers()
for i in response['LoadBalancers']:
    if i['Type'] == 'application':

        elbv2.append(i['LoadBalancerArn'])

for i in elbv2:
    response1 = client.describe_tags(
                 ResourceArns= [ i ] )

    for i in response1['TagDescriptions']:
    
     tags = {
             tag['Key']: tag['Value']
             for tag in i['Tags']
             }

     if 'Integrity' and 'Confidentiality' in tags:
               if (tags['Confidentiality'])== '1' and (tags['Integrity']) == '1':
                elbv1ARN.append(i['ResourceArn'])


protected = shieldpro.list_protections(MaxResults=100)

for i in protected['Protections']:
    pro.append(i['ResourceArn'])

print("Missing values in protected resources list:", (set(elbv1ARN).difference(pro)))
