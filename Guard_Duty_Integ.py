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

account_id = '390012270948'
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
           a_id = boto3.client('sts').get_caller_identity().get('Account')
           response = self.client.list_detectors()

           if  response['DetectorIds']:
               Detector_id = response['DetectorIds'][0]
           else:
               return []

           response1 = self.client.get_master_account(
                DetectorId = Detector_id
           )

           if  response1['Master']['AccountId'] == account_id :
               if response1['Master']['RelationshipStatus'] == 'Enabled':
                   return a_id
               elif response1['Master']['RelationshipStatus'] != 'Enabled':
                   #display = ('[INFO] GuardDuty is in {} status'.format(response1['Master']['RelationshipStatus']))
                   #return display
                   return (a_id,response1['Master']['RelationshipStatus'])

       except KeyError :
           return []
       except Exception:
           raise


if __name__ == '__main__':
    # Parse args and create some global constants which require some function calls
    # args = parse_args()
    ORGANIZATIONS_CREDENTIALS = assume_role(ORGANIZATIONS_ACCOUNT, ORGANIZATIONS_ROLE)
    organizations = organizations.Organizations(ORGANIZATIONS_CREDENTIALS, debug=True)
    aab_ou_id = organizations.find_ou_id(AAB_OU_PATH)
    all_aab_accounts = organizations.get_child_accounts(aab_ou_id, recursive=True, inactive=False)

    invalid_ou = [
                   'ABN Amro > Closed',
                   'ABN Amro > Engineering',
                   'ABN Amro > Decommission',
                   'ABN Amro > Setup > Untouched'
                 ]

    no_guardduty_accounts = []
    guardduty_accounts = []

    for acct_id in all_aab_accounts:

     if organizations.get_ou_tree_for_child(acct_id) not in invalid_ou:
      if acct_id != account_id:
       #print('=== {} === '.format(acct_id))

       try:
            account_credentials = assume_role(
                account_id=acct_id,
                role_name='OrganizationAccountAccessRole',
                credentials=ORGANIZATIONS_CREDENTIALS
            )
       except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('[WARN] Cannot assume role into account, access denied.')
                print('[DEBUG] OU tree of account: {}'.format(
                    organizations.get_ou_tree_for_child(acct_id)))
                continue
            else:
                raise

       gaurd_duty = Guard_Duty(account_credentials).get_guardduty_accounts()

       if gaurd_duty:
           print('--- {} --- [INFO] GUARDDUTY is ENABLED in account '.format(acct_id))
           guardduty_accounts.append(acct_id)
       if not gaurd_duty:
           print('[INFO] GUARDDUTY is NOT ENABLED in account ')
           no_guardduty_accounts.append(acct_id)
       elif gaurd_duty == 'access_denied':
            print('[DEBUG] OU tree of account: {}'.format(
                organizations.get_ou_tree_for_child(acct_id)))
      else:
           print('')

    print('[INFO] Total of {} having GUARDDUTY ENABLED , {} have not'.format(
        len(guardduty_accounts), len(no_guardduty_accounts)))
    if len(no_guardduty_accounts) == 0 :
       print('All {} accounts having GUARDDUTY enabled'.format(len(guardduty_accounts)))
    else:
       print('')
       print('[INFO] Account(s) with no GUARDDUTY enabled yet :')
       print('')
       print(no_guardduty_accounts)
       print('')
