
import boto3
import csv
from botocore.exceptions import ClientError
import logging
import re
from common import Account
import os
logger = logging.getLogger()

region = []
servicename = []
resource = []
limit_amount = []
current_usage = []
account = []
status = []
new = []




def service_limit_check():
        checkid=[]
        aggregator = []

        #account_id = boto3.client('sts').get_caller_identity().get('Account')

        client = self.account.get_client('support','us-east-1')


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
                account.append(account_id)
                status.append('WARNING')

                limit_details=zip(region,servicename,resource,limit_amount, current_usage,account,status)
                header = ['Region', 'Service','Resource','Limit Amount','Current Usage','Account','Status']
                aggregator = region + servicename + resource + limit_amount + current_usage + account + status
                return  aggregator

service_limit_check()



