#!/usr/bin/env python
"""
This script can be used to find the status of the Direct Connect VIF's
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


client = boto3.client('guardduty')
account_idd = '390012270948'


def assume_role(account_id, role_name, credentials={}):
    """
    Assume a role and return credentials, optionally by using specified credentials
    """
    # print('[INFO] Assuming role "{}" in account {}'.format(role_name, account_id))
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

class Guardduty:
    def __init__(self, credentials, account_id, region):
        self.account_id = account_id
        self.client = boto3.client('guardduty',
                                   aws_access_key_id=credentials['AccessKeyId'],
                                   aws_secret_access_key=credentials['SecretAccessKey'],
                                   aws_session_token=credentials['SessionToken'],
                                   config=CONFIG
        )

        def get_guardduty_accounts(self):
            try:
                
                response = self.client.list_detectors()

                if  response['DetectorIds']:
                    Detector_id = response['DetectorIds'][0]
                else:
                    return []

                response1 = self.client.get_master_account(
                    DetectorId = Detector_id
                )

                if  response1['Master']['AccountId'] == account_idd:
                    if response1['Master']['RelationshipStatus'] == 'Enabled':
                        print('Accout is enabled {}'.format(account_id))
                    elif response1['Master']['RelationshipStatus'] != 'Enabled':                        
                        return (account_id,response1['Master']['RelationshipStatus'])

            except KeyError :
                return []
            except Exception:
                raise
            
def main(account_id):

    if account_id:
        try:
            account_credentials = assume_role(
                account_id=account,
                role_name='OrganizationAccountAccessRole',
                credentials=ORGANIZATIONS_CREDENTIALS
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('[WARN] Cannot assume role into account, access denied.')
                continue
            else:
                raise

        Guardduty(account_credentials, account).get_guardduty_accounts()
    else:
        print('Not Found')
         

def parse_args():

    parser = ArgumentParser(description='Account Cleanup script')
    intake = parser.add_mutually_exclusive_group(required=True)

    intake.add_argument(
        '-a', '--account-id',
        dest='account_id',
        help='Passing account to check.',
        type=str
    )


    if len(sys.argv) == 1:
        parser.print_help()
        exit(2)
    return parser.parse_args()

if __name__ == '__main__':
   args = parse_args()
   get_guardduty_accounts(account_id=args.account_id)   # all_regions=args.all_regions)
