
import boto3
from botocore.config import Config
from boto3.session import Session
import sys
import yaml
import time
import functools


def memoize(fn):
    cache = fn.cache = {}

    @functools.wraps(fn)
    def memoizer(*args, **kwargs):
        if args not in cache:
            cache[args] = fn(*args, **kwargs)
        return cache[args]

    return memoizer


def profile(fn):
    @functools.wraps(fn)
    def with_profiling(*args, **kwargs):
        start_time = time.time()

        ret = fn(*args, **kwargs)

        elapsed_time = time.time() - start_time

        print_and_flush('{:40}|{:10.4f}'.format(
            fn.__name__,
            elapsed_time
        ))

        return ret

    return with_profiling


def print_and_flush(message):
    print message
    sys.stdout.flush()


class Account:

    def __init__(self, account_id=None, role_name=None):
        self.config = Config(max_pool_connections=50, retries={'max_attempts': 20})
        self.region = boto3.session.Session().region_name

        if account_id:
            credentials = self.get_assumed_credentials(account_id, role_name)
            access_key_id = credentials['AccessKeyId']
            secret_access_key = credentials['SecretAccessKey']
            session_token = credentials['SessionToken']
        else:
            access_key_id = None
            secret_access_key = None
            session_token = None

        self.session = Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
        )

        self.id = self.get_client('sts').get_caller_identity()['Account']
        try:
            self.alias = self.get_client('iam').list_account_aliases()['AccountAliases'][0]
        except:
            self.alias = self.id

    @memoize
    def get_client(self, service_name, region=None):
        if not region:
            region = self.region

        return self.session.client(service_name,
            config=self.config,
            region_name=region,
        )

    @memoize
    def get_resource(self, resource_name, region=None):
        if not region:
            region = self.region

        return self.session.resource(resource_name,
            config=self.config,
            region_name=region,
        )

    def get_assumed_credentials(self, account_id, role_name):
        # Create an STS client object that represents a live connection to the
        # STS service.
        client = boto3.client('sts', config=self.config)

        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name.
        assumedRoleObject = client.assume_role(
            RoleArn='arn:aws:iam::%s:role/%s' % (account_id, role_name),
            RoleSessionName='session'
        )

        print_and_flush('Assuming role into %s' % account_id)

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls.
        return assumedRoleObject['Credentials']
c