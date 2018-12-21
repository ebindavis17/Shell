#!/usr/bin/env python
"""
Handles AWS Organizations
"""

from __future__ import print_function

import boto3
import cachetools
import time
from botocore.exceptions import ClientError, WaiterError
from functools import wraps

__version__ = '0.3'

INACTIVE_OU_PATHS = [
    'ABN Amro > Closed',
    'ABN Amro > Decommission',
    'ABN Amro > Suspended',
]

# Both error codes are used on different AWS API's, meaning the same
LIMIT_ERRORS = ['LimitExceededException', 'ClientLimitExceededException']

find_ou_id_cache = cachetools.LRUCache(maxsize=128)
get_ou_tree_cache = cachetools.LRUCache(maxsize=128)
get_ou_name_cache = cachetools.LRUCache(maxsize=128)

def exception_handler(original_function, number_of_tries=4, delay=3):
    """
    Provide an exception handler with exponential backoff for AWS API calls
    """
    @wraps(original_function)
    def retried_function(*args, **kwargs):
        for i in range(number_of_tries):
            try:
                return original_function(*args, **kwargs)
            except ClientError as error:
                error_code = error.response['Error']['Code']
                if error_code in LIMIT_ERRORS:
                    backoff = delay * (2**i)
                    time.sleep(backoff)
                elif error_code == 'ChildNotFoundException':
                    print('[ERROR] Cant find OU or account with the ChildId specified')
                    raise
                elif 'CreateAccount' in str(error):
                    print('[ERROR] Exception occurred while creating new account')
                    raise
                elif 'MoveAccount' in str(error):
                    print('[ERROR] Exception occurred while trying to move account to OU')
                    raise
                else:
                    raise
    return retried_function


class Organizations:

    def __init__(self, credentials, silent=False, debug=False):
        self.silent = silent
        self.debug = debug
        self.client = boto3.client('organizations',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )

    @exception_handler
    def get_root_id(self):
        paginator = self.client.get_paginator('list_roots')
        response_iterator = paginator.paginate()

        roots = [
            root
            for response in response_iterator
            for root in response['Roots']
        ]

        if len(roots) != 1:
            raise Exception('Expected exactly one root in Organizations tree')

        return roots[0]['Id']

    @exception_handler
    def list_accounts(self):
        paginator = self.client.get_paginator('list_accounts')
        response_iterator = paginator.paginate(PaginationConfig={'MaxItems': 100000})

        if not self.silent:
            print('[INFO] Receiving all accounts within the Organization (for reference)')
        return [
            account
            for response in response_iterator
            for account in response['Accounts']
        ]

    @exception_handler
    def list_parents(self, child_id):
        """ child_id can be account ID or OU ID """
        paginator = self.client.get_paginator('list_parents')
        response_iterator = paginator.paginate(ChildId=child_id)
        return [
            account_parent['Id']
            for response in response_iterator
            for account_parent in response['Parents']
        ]

    @cachetools.cached(get_ou_name_cache)
    @exception_handler
    def get_ou_name(self, ou_id):
        response = self.client.describe_organizational_unit(OrganizationalUnitId=ou_id)
        return response['OrganizationalUnit']['Name']

    @exception_handler
    def get_organizational_units_for_parent(self, parent_id):
        paginator = self.client.get_paginator('list_organizational_units_for_parent')
        response_iterator = paginator.paginate(ParentId=parent_id)

        return [
            child
            for response in response_iterator
            for child in response['OrganizationalUnits']
        ]

    @cachetools.cached(get_ou_tree_cache)
    @exception_handler
    def get_ou_tree_for_child(self, child_id):
        """
        Finds OU tree of a child (account/OU) by fetching the parent until reaching root
        """
        parent_ou = self.list_parents(child_id)[0]
        if child_id.startswith('ou-'):
            tree_list = [self.get_ou_name(child_id)]
        else:
            tree_list = []

        def _recurse_parents(parent_id):
            parent_ou = self.list_parents(parent_id)[0]
            if parent_ou.startswith('ou-'):
                tree_list.append(self.get_ou_name(parent_ou))
                return _recurse_parents(parent_ou)
            elif parent_ou.startswith('r-'):
                tree_list.reverse()  # Reverse list so the tree is not inversed
                return ' > '.join(tree_list)
            else:
                print('[WARN] Unexpected ID returned for account/OU while trying to get the OU tree: {}, cannot determine if root or OU'.format(parent_ou))

        if parent_ou.startswith('ou-'):
            tree_list.append(self.get_ou_name(parent_ou))
            return _recurse_parents(parent_ou)
        elif child_id.startswith('ou-'):
            return child_id
        else:
            # Child is created under root
            return ''

    @exception_handler
    def get_child_accounts(self, parent_id, recursive=False, inactive=True):
        """
        Retrieve child accounts of an OU ID, optionally recursive and exluding inactive accounts (suspended, decommisioned, etc.)
        """
        paginator = self.client.get_paginator('list_accounts_for_parent')
        response_iterator = paginator.paginate(ParentId=parent_id)

        if inactive:
            excluded_ou_ids = [self.find_ou_id(x) for x in INACTIVE_OU_PATHS]
        else:
            excluded_ou_ids = []

        def _recurse_ous(ou_ids=[], child_accounts=[]):
            for ou in ou_ids:
                if ou not in excluded_ou_ids:
                    child_ous = [x['Id'] for x in self.get_organizational_units_for_parent(ou)]
                    # Add accounts to the list
                    child_accounts.extend(self.get_child_accounts(ou))
                    if child_ous:
                        # Recurse through child OU's, function returns an updated list with accounts each time
                        child_accounts = _recurse_ous(ou_ids=child_ous,
                                                      child_accounts=child_accounts)
            else:
                return child_accounts

        if recursive:
            return _recurse_ous(ou_ids=[parent_id])
        else:
            accounts = [
                account['Id']
                for response in response_iterator
                for account in response['Accounts']
            ]
            if not self.silent:
                print('[INFO] {} accounts found in {}{}'.format(
                    len(accounts),
                    parent_id,
                    '' if not self.debug else ' ({})'.format(
                        self.get_ou_tree_for_child(parent_id)
                        )
                    )
                )
            return accounts

    @cachetools.cached(find_ou_id_cache)
    @exception_handler
    def find_ou_id(self, path, iteration=0, parent_ou_id=None):
        """ Find OU ID for path, recurses through the tree until it finds the last segment of the path """
        segments = path.split(' > ')
        # If no parent is given, start at root
        if not parent_ou_id:
            parent_ou_id = self.get_root_id()

        # Recurse through OU's to find the OU ID for the given path
        ous = self.get_organizational_units_for_parent(parent_ou_id)
        for ou in ous:
            if ou['Name'] == segments[iteration]:
                if iteration+1 < len(segments):
                    return self.find_ou_id(path, iteration+1, ou['Id'])
                else:
                    return ou['Id']
        else:
            raise Exception('[ERROR] Given path "{}" does not resolve to an OU'.format(path))

    def get_accounts_for_path(self, path, recursive=False):
        ou_id = self.find_ou_id(path)
        return self.get_child_accounts(ou_id, recursive)

    @exception_handler
    def move_account_to_ou_id(self, account_id, source_ou_id, destination_ou_id):
        if source_ou_id != destination_ou_id:
            if not self.silent:
                print('[INFO] Moving account "{}" from "{}" to "{}"'.format(
                    account_id, source_ou_id, destination_ou_id))
            return self.client.move_account(
                AccountId=account_id,
                SourceParentId=source_ou_id,
                DestinationParentId=destination_ou_id,
            )
        else:
            print('[INFO] Account is already in the destination OU')

    @exception_handler
    def move_account_to_ou_path(self, account_id, source_ou_path, destination_ou_path):
        source_ou_id = self.find_ou_id(source_ou_path)
        destination_ou_id = self.find_ou_id(destination_ou_path)
        return self.move_account_to_ou_id(account_id, source_ou_id, destination_ou_id)

    @exception_handler
    def create_and_move_account(self, account_name, account_email, ou_id):
        """
        Create new AWS account and add it to a given OU.
        Note: Does not specify RoleName (default: 'OrganizationAccountAccessRole') or IamUserAccessToBilling (default: 'ALLOW')
        """
        create_account_response = self.client.create_account(
            Email=account_email,
            AccountName=account_name)

        # Wait a bit before checking status
        time.sleep(5)
        account_status = 'IN_PROGRESS'
        while account_status == 'IN_PROGRESS':
            create_account_status_response = self.client.describe_create_account_status(
                CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
            create_account_status = create_account_status_response.get('CreateAccountStatus', {})
            print('[INFO] Create account status - {}'.format(create_account_status_response.get('CreateAccountStatus')))
            account_status = create_account_status.get('State')

        if account_status == 'SUCCEEDED':
            account_id = create_account_status.get('AccountId')
            print('[INFO] Account {} created successfully'.format(account_id))
        elif account_status == 'FAILED':
            failure_reason = create_account_status.get('FailureReason', 'No reason given by API')
            print('[DEBUG] Account status response: {}'.format(create_account_status_response))
            raise Exception('[ERROR] Account creation failed: {}'.format(failure_reason))

        # Move to 'Untouched' OU
        print('[INFO] Moving account {} to {}'.format(account_id, ou_id))
        self.move_account_to_ou_id(account_id, self.get_root_id(), ou_id)

        return account_id
