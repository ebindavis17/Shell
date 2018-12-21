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

# Import libaries from ../lib
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import lib.metadata as metadata
import lib.organizations as organizations

CONFIG = Config(retries={'max_attempts': 10})
ORGANIZATIONS_ACCOUNT = '064670468982'  # aab-billing
ORGANIZATIONS_ROLE = 'cbsp-organizations-account-lifecycle-handler'
SUPPORTED_REGION_MAP = {
    'Ireland': 'eu-west-1',
    'Frankfurt': 'eu-central-1',
}


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


class DirectConnect:

    def __init__(self, credentials, account_id, region):
        self.account_id = account_id
        self.region = region
        self.client = boto3.client('directconnect',
                                   region_name=self.region,
                                   aws_access_key_id=credentials['AccessKeyId'],
                                   aws_secret_access_key=credentials['SecretAccessKey'],
                                   aws_session_token=credentials['SessionToken'],
                                   config=CONFIG
        )

    def get_vifs(self):
        intf = self.client.describe_virtual_interfaces()
        return [
          (vif['virtualInterfaceId'], vif['virtualInterfaceState'])
          for vif in intf['virtualInterfaces']
        #   if vif['virtualInterfaceState'] == 'confirming'
        ]

    def report_vif_state(self):
        # confirming | verifying | pending | available | down | deleting | deleted | rejected
        # dubious_states = ['down', 'deleting', 'deleted', 'rejected']
        # unready_states = ['confirming', 'verifying', 'pending', 'down', 'deleting', 'deleted', 'rejected']
        vifs = self.get_vifs()
        print('=== {} ({}) ==='.format(self.account_id, self.region))
        if len(vifs) == 2:
            if not all([vif_state == 'available' for vif_id, vif_state in vifs]):
                print('[WARN] VIFs not (all) in available state:\n{}'.format(vifs))
        elif not vifs:
            print('[WARN] No VIFs present')
        elif len(vifs) > 2:
            print('[WARN] More than 2 VIFs present:\n{}'.format(vifs))


def main(account_id, ou_path, region=None, recursive_ou_lookup=False):
    if ou_path:
        print('[INFO] Finding accounts in OU path "{}" {}'.format(
            ou_path, 'recursively' if recursive_ou_lookup else 'non-recursively'))
        accounts = [i for i in organizations.get_accounts_for_path(ou_path, recursive_ou_lookup)]
    elif account_id:
        accounts = [account_id]
    print('[INFO] Querying {} accounts:\n  {}'.format(len(accounts), accounts))

    if region:
        regions = [region]
    elif ou_path:
        two_last_ous = [ou_path.split(' > ')[-1], ou_path.split(' > ')[-2]]
        regions = [
            SUPPORTED_REGION_MAP[ou]
            for ou in two_last_ous
            if ou in SUPPORTED_REGION_MAP
        ]
        if not regions:
            regions = [v for k,v in SUPPORTED_REGION_MAP.items()]
    else:
        regions = [v for k,v in SUPPORTED_REGION_MAP.items()]

    for account in accounts:
        for region in regions:
            # Get admin credentials for the account
            # When account alias already existed, uses acquired alias status info for the account ID
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

            DirectConnect(account_credentials, account, region).report_vif_state()



def parse_args():
    parser = ArgumentParser(description='Account Cleanup script')
    intake = parser.add_mutually_exclusive_group(required=True)
    intake.add_argument(
        '-a', '--account-id',
        dest='account_id',
        help='Organizational Unit ID for which the child accounts will be prepared. By default non-recursively.',
        type=str
    )
    intake.add_argument(
        '-ou', '--organizational-unit-path',
        dest='ou_path',
        help='Organizational Unit path for which child accounts will be queried. By default non-recursive.',
        type=str
    )
    intake.add_argument(
        '-r', '--region',
        dest='region',
        help='Region to check VIFs in. Note: Not necessary if you provide a regional OU. If region cannot be determined, it will check for all the CBSP supported regions.',
        type=str
    )
    parser.add_argument(
        '-or', '--recursive-ou-lookup',
        dest='recursive_ou_lookup',
        help='Use recursion to select accounts from child OUs (infinite levels) too, only works with "-ou"',
        action='store_true'
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

    main(account_id=args.account_id,
         ou_path=args.ou_path,
         region=args.region,
         recursive_ou_lookup=args.recursive_ou_lookup)