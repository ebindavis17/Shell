#!/usr/bin/env python
"""
This script can be used to find the status of the GuardDuty in ABN Amro OU
"""
from __future__ import print_function
from __future__ import unicode_literals

import boto3
import json
import sys

from argparse import ArgumentParser, ArgumentTypeError
from botocore.config import Config
from botocore.exceptions import ClientError
from ipaddress import ip_network
from os import path

# Import libaries from ../lib
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import lib.metadata as metadata
import lib.organizations as organizations

ORGANIZATIONS_ACCOUNT = '064670468982'  # aab-billing
ORGANIZATIONS_ROLE = 'cbsp-organizations-account-lifecycle-handler'

AAB_OU_PATH = 'ABN Amro'
id_account = '390012270948'
role = 'OrganizationAccountAccessRole'


def assume_role(account_id, role_name, credentials={}):
   """
   Assume a role and return credentials, optionally by using specified credentials
   """
   #print('[INFO] Assuming role "{}" in account {}'.format(role_name, account_id))
   sts_client = boto3.client('sts',
                             aws_access_key_id=credentials.get('AccessKeyId'),
                             aws_secret_access_key=credentials.get('SecretAccessKey'),
                             aws_session_token=credentials.get('SessionToken'),
   )
   role_arn = 'arn:aws:iam::{}:role/{}'.format(account_id, role_name)

   # Call the assume_role method of the STSConnection object and pass the role
   # ARN and a role session name.
   assumed_role_object = sts_client.assume_role(
       RoleArn=role_arn,
       RoleSessionName='AccountCreationSession')

   return assumed_role_object['Credentials']

class Guard_Duty:

   def __init__(self, credentials, account_id, region):
       self.account_id = account_id,
       self.region = region,
       self.client = boto3.client('guardduty',
                                    region_name=self.region,
                                    aws_access_key_id=credentials['AccessKeyId'],
                                    aws_secret_access_key=credentials['SecretAccessKey'],
                                    aws_session_token=credentials['SessionToken'],
                                )

   def get_guardduty_accounts(self):

       try:
           account_id = account_id
           #a_id = boto3.client('sts').get_caller_identity().get('Account')
           response = self.client.list_detectors()

           if  response['DetectorIds']:
              Detector_id = response['DetectorIds'][0]
           else:
              return []

           response1 = self.client.get_master_account(
               DetectorId = Detector_id
           )

           if  response1['Master']['AccountId'] == id_account:
               if response1['Master']['RelationshipStatus'] == 'Enabled':
                   print('GuardDuty is [ ENABLED ] in account {}'.format(account_id))
                   #return account_id
               elif response1['Master']['RelationshipStatus'] != 'Enabled':
                  #display = ('[INFO] GuardDuty is in {} status'.format(response1['Master']['RelationshipStatus']))
                  #return display
                  print('GuardDuty is [ NOT ENABLED ] in account {}'.format(account_id))
                  #return (account_id,response1['Master']['RelationshipStatus'])

       except KeyError :
           return []
       except Exception:
           raise

def main(account_id):

   regions = [
       'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 
       'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 
       'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
       ]

   ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
   organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, debug=True)
   aab_ou_id = organizations.find_ou_id(AAB_OU_PATH)
   all_aab_accounts = organizations.get_child_accounts(aab_ou_id, recursive=True, inactive=False)
   
   for accounts in all_aab_accounts:
    if account_id in accounts:
       if region:
           try:
               account_credentials = assume_role(
                   account_id=account_id,
                   role_name='OrganizationAccountAccessRole',
                   credentials=ORGANIZATIONS_CREDENTIALS
               )
           except ClientError as e:
               if e.response['Error']['Code'] == 'AccessDenied':
                   print('[WARN] Cannot assume role into account, access denied.')
                   continue
               else:
                   raise

           Guard_Duty(account_credentials, account_id).get_guardduty_accounts()

def parse_args():
   parser = ArgumentParser(description='Account Cleanup script')
   intake = parser.add_mutually_exclusive_group(required=True)
   intake.add_argument(
       '-a', '--account-id',
       dest='account_id',
       help='Organizational Unit ID for which the child accounts will be prepared. By default non-recursively.',
   )

   if len(sys.argv) == 1:
       parser.print_help()
       exit(2)

   return parser.parse_args()

if __name__ == '__main__':
    # Parse args and create some global constants which require some function calls
    args = parse_args()
    ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
    organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, silent=True)
    metadata = metadata.Metadata()

    main(account_id=args.account_id
#         ou_path=args.ou_path,
#         region=args.region,
#         recursive_ou_lookup=args.recursive_ou_lookup
        )
