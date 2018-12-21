import boto3
import csv
from botocore.exceptions import ClientError
import logging
import re
import os
logger = logging.getLogger()

role_name='aab-administrator'
HOME = os.getenv('HOME')

region = []
servicename = []
resource = []
limit_amount = []
current_usage = []
account = []
status = []
new = []

account_id_list=['109820128062','444640145934','438908125245','995208321268','853493370704','703926814710','690762787000','627175348114','846660817072','145199091356','213361310488','672410507030','750692453665','529370137371','917740138688','510005241452','996868193516','110535923373','574439287843','205011823303','907826395456','415757711927','753773468360','015264156895','848939901609','913545700946','325411244799','624188900956','430442681156']

account_details={'109820128062': 'aab-acccustdta','444640145934':'aab-acccustf','438908125245':'aab-acccustp','995208321268':'aab-channelsdta','853493370704':'aab-channelsf','703926814710':'aab-channelsp','690762787000':'aab-cisodta','627175348114':'aab-cisof','846660817072':'aab-cisop','145199091356':'aab-credmortdta','213361310488':'aab-credmortf','672410507030':'aab-credmortp','750692453665':'aab-functionsdta','529370137371':'aab-functionsf','917740138688':'aab-functionsp','510005241452':'aab-itsvcsdta','996868193516':'aab-itsvcsf','110535923373':'aab-itsvcsp','574439287843':'aab-marketsdta','205011823303':'aab-marketsf','907826395456':'aab-marketsp','415757711927':'aab-otherdta','753773468360':'aab-otherf','015264156895':'aab-otherp','848939901609':'aab-sharedsvcsdta','913545700946':'aab-sharedsvcsp','325411244799':'aab-transactionsdta','624188900956':'aab-transactionsf','430442681156':'aab-transactionsp'}

#account_id_list=['109820128062','444640145934','438908125245','995208321268','853493370704','703926814710','690762787000','627175348114','846660817072','145199091356','213361310488','750692453665','529370137371','917740138688','996868193516','110535923373','574439287843','205011823303','907826395456','415757711927','753773468360','015264156895','848939901609','913545700946','325411244799','624188900956','430442681156']

#account_details={'109820128062': 'aab-acccustdta','444640145934':'aab-acccustf','438908125245':'aab-acccustp','995208321268':'aab-channelsdta','853493370704':'aab-channelsf','703926814710':'aab-channelsp','690762787000':'aab-cisodta','627175348114':'aab-cisof','846660817072':'aab-cisop','145199091356':'aab-credmortdta','213361310488':'aab-credmortf','750692453665':'aab-functionsdta','529370137371':'aab-functionsf','917740138688':'aab-functionsp','996868193516':'aab-itsvcsf','110535923373':'aab-itsvcsp','574439287843':'aab-marketsdta','205011823303':'aab-marketsf','907826395456':'aab-marketsp','415757711927':'aab-otherdta','753773468360':'aab-otherf','015264156895':'aab-otherp','848939901609':'aab-sharedsvcsdta','913545700946':'aab-sharedsvcsp','325411244799':'aab-transactionsdta','624188900956':'aab-transactionsf','430442681156':'aab-transactionsp'}


def get_assumed_credentials(account_id, role_name):

    sts_client = boto3.client('sts')

    try:
        assume_role_object = sts_client.assume_role(
            RoleArn='arn:aws:iam::%s:role/%s' % (account_id, role_name),
            RoleSessionName='session'
        )

    except ClientError as e:
        logger.error('AssumeRole for %s in %s failed with: %s' % (role_name, account_id,
                                                                  e.response['Error']['Message']))

    else:
        logger.debug('AssumeRole succeeded for %s in %s' % (role_name, account_id))
        return assume_role_object['Credentials']

def assume_role_accnt(account_id_list):
    for id in account_id_list:
        credentials=get_assumed_credentials(id, role_name)
        assumed_credentials_per_profile = {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken'],
        'account_id': id
        }
        yield assumed_credentials_per_profile

def service_limit_check(account_details):
   checkid=[]
   for credentials_list in assume_role_accnt(account_id_list):
       client=boto3.client('support','us-east-1',aws_access_key_id=credentials_list['aws_access_key_id'], aws_secret_access_key=credentials_list['aws_secret_access_key'], aws_session_token=credentials_list['aws_session_token'])

       trustedadvisor_checks = client.describe_trusted_advisor_checks(
                               language="en"
                               )


       for service in trustedadvisor_checks['checks']:

           if service['category'] == 'service_limits':
               if service['id'] not in checkid:
                   checkid.append(service['id'])

       for allcheckids in checkid:

           trustedadvisor_result = client.describe_trusted_advisor_check_result(
                                   checkId=allcheckids,
                                   language='en'
                                   )


           for checkresult in trustedadvisor_result['result']['flaggedResources']:

               if checkresult['status'] == 'warning' or  checkresult['status'] == 'error':
                   region.append(checkresult['metadata'][0])
                   servicename.append(checkresult['metadata'][1])
                   resource.append(checkresult['metadata'][2])
                   limit_amount.append(checkresult['metadata'][3])
                   current_usage.append(checkresult['metadata'][4])
                   account.append(account_details[credentials_list['account_id']])
                   status.append('WARNING')

   limit_details=zip(region,servicename,resource,limit_amount, current_usage,account,status)
   header = ['Region', 'Service','Resource','Limit Amount','Current Usage','Account','Status']
   csvfile = "{}/testingSS3.csv".format(HOME)
   with open(csvfile, "w") as testing:
           writer = csv.writer(testing, lineterminator='\n')
           writer.writerow(header)
           writer.writerows(limit_details)

def s3(account_details):

   for credentials_list in assume_role_accnt(account_id_list):
       client_buckets=boto3.client('s3',aws_access_key_id=credentials_list['aws_access_key_id'], aws_secret_access_key=credentials_list['aws_secret_access_key'], aws_session_token=credentials_list['aws_session_token'])

       buckets=[]

       buckets_list= client_buckets.list_buckets()
       for i in buckets_list['Buckets']:
           buckets.append(i['Name'])
       if len(buckets) > 80 :

           region.append("eu-west-1")
           servicename.append("S3")
           resource.append("Buckets")
           limit_amount.append("-")
           current_usage.append(len(buckets))
           account.append(account_details[credentials_list['account_id']])
           status.append("WARNING")


   limit_details=zip(region,servicename,resource,limit_amount,current_usage,account,status)
   header = ['Region','Service','Resource','Limit Amount','Current Usage','Account','Status']
   csvfile = "{}/Service_Limit.csv".format(HOME)
   with open(csvfile, "w") as testing:
           writer = csv.writer(testing, lineterminator='\n')
           writer.writerow(header)
           writer.writerows(limit_details)

def ec2_run(account_details):

   for credentials_list in assume_role_accnt(account_id_list):
       client_ec2=boto3.client('ec2',aws_access_key_id=credentials_list['aws_access_key_id'], aws_secret_access_key=credentials_list['aws_secret_access_key'], aws_session_token=credentials_list['aws_session_token'])

       new=[]
       instance_list = client_ec2.describe_instances()

       for i in instance_list['Reservations']:
           for j in i['Instances']:
               if  j['State']['Name'] == 'running':
                   new.append( j['State']['Name'])

       if len(new) > 15 :

           region.append("eu-west-1")
           servicename.append("EC2")
           resource.append("Instances")
           limit_amount.append("-")
           current_usage.append(len(new))
           account.append(account_details[credentials_list['account_id']])
           status.append("WARNING")

   limit_details=zip(region,servicename,resource,limit_amount,current_usage,account,status)
   header = ['Region','Service','Resource','Limit Amount','Current Usage','Account','Status']
   csvfile = "{}/Service_Limit.csv".format(HOME)
   with open(csvfile, "w") as testing:
           writer = csv.writer(testing, lineterminator='\n')
           writer.writerow(header)
           writer.writerows(limit_details)

service_limit_check(account_details)
s3(account_details)
ec2_run(account_details)
