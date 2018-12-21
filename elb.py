import boto3

client = boto3.client('elbv2')
shieldpro = boto3.client('shield','us-east-1')


def lambda_handler(event, context):
    response = client.describe_load_balancers()
    for i in response['LoadBalancers']:
        if i['Type'] == 'application':

        elbv2.append(i['LoadBalancerArn'])
#    print(elbv2)

for i in elbv2:
    response1 = client.describe_tags(
                 ResourceArns= [ i ] )

    for i in response1['TagDescriptions']:
     #print(i['Tags'])
     tags = {
             tag['Key']: tag['Value']
             for tag in i['Tags']
             }

     if 'Integrity' and 'Confidentiality' in tags:
               if (tags['Confidentiality'])== '1' and (tags['Integrity']) == '1':
                elbv1ARN.append(i['ResourceArn'])

print(elbv1ARN)

    response = client.list_protections(MaxResults=100)
    for i in response['Protections']:
        pro.append(i['ResourceArn'])
    print(len(pro))
        