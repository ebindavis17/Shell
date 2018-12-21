#!/usr/bin/env python
"""
Requests Enterprise Support for all accounts beneath the ABN Amro OU (which dont have it yet)
"""

from __future__ import print_function

import boto3
import sys

from botocore.exceptions import ClientError

# Import libaries from ../lib
from os import path
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import lib.organizations as organizations


### AWS Organizations constants
ORGANIZATIONS_ACCOUNT = '064670468982'  # aab-billing
ORGANIZATIONS_ROLE = 'cbsp-organizations-account-lifecycle-handler'

AAB_OU_PATH = 'ABN Amro'

DetectorId = '8cb2c2c80e40a1f15564bbe531a1b5ef'

acc_id = '390012270948'
role = 'OrganizationAccountAccessRole'

def assume_role(account_id, role_name, credentials={}):
    """
    Assume a role and return credentials, optionally by using specified credentials
    """
    print('[INFO] Assuming role "{}" in account {}'.format(role_name, account_id))
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

    def __init__(self,credentials,silent=False, debug=False):


        self.silent = silent
        self.debug = debug
        self.client = boto3.client('guardduty',
            #region_name='us-east-1',  # Support API only lives in us-east-1
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )

    def get_guardduty_accounts(self):

       try:
           paginator = self.client.get_paginator('list_members')

           response_iterator = paginator.paginate(
               DetectorId=DetectorId,
               OnlyAssociated='FALSE'
           )

           for response in response_iterator:
               for member in response['Member']:
                   if member['RelationshipStatus'] == 'Enabled':
                       return member['AccountId']


       except Exception:
           raise


if __name__ == '__main__':
    # Parse args and create some global constants which require some function calls
    # args = parse_args()
    ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
    organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, debug=True)
    aab_ou_id = organizations.find_ou_id(AAB_OU_PATH)
    all_aab_accounts = organizations.get_child_accounts(aab_ou_id, recursive=True, inactive=False)

    no_guardduty_accounts = []
    guardduty_accounts = []

    account_credentials = assume_role(
                account_id=acc_id, #aab-sharedsvcs-master
                role_name=role,
                credentials=ORGANIZATIONS_CREDENTIALS
    )

    print('')
    for acct_id in all_aab_accounts:
       print('=== {} ==='.format(acct_id))

       print('AC ->>>>'.format(account_credentials))
       gaurd_duty = Guard_Duty(account_credentials).get_guardduty_accounts()

       if acct_id not in gaurd_duty:
           print('[INFO] GuardDuty is NOT ENABLED in account :[ {} ]'.format(acct_id))
       else:
           print('[INFO] GuardDuty is ENABLED in account :[ {} ]'.format(acct_id))

#        print(type(gaurd_duty))

#       if gaurd_duty:
#            guardduty_accounts.append(acct_id)
#        if not gaurd_duty:
#            print('[INFO] Account has no GuardDuty ENABLED')
#            no_guardduty_accounts.append(acct_id)
#        elif gaurd_duty == 'access_denied':
#            print('[DEBUG] OU tree of account: {}'.format(
#                organizations.get_ou_tree_for_child(acct_id)))

#    print('[INFO] Total of {} having GuardDuty ENABLED, {} have not'.format(
#        len(guardduty_accounts), len(no_guardduty_accounts)))

