import boto3
from botocore.exceptions import ClientError
import json
import re
from common import Account, get_account_ids
from datetime import datetime


class ResourceComplianceReport:

    def __init__(self, account):
        self.account = account

    def get_stack_id(self, stack):
        return re.sub(r'^arn:aws:cloudformation:.*:.*:stack/.*/(.*)$', r'\1', stack['StackId'])

    def get_stack_name(self, stack):
        return stack['StackName']

    def get_resource_type(self, resource):
        return resource['ResourceType']

    def get_resource_id(self, resource):
        # Catch rare cases where there is no ID to be found
        try:
            return resource['PhysicalResourceId']
        except KeyError:
            return None

    def does_resource_exist(self, resource):
        return resource['ResourceStatus'] not in [
            'CREATE_IN_PROGRESS',
            'CREATE_FAILED',
            'DELETE_COMPLETE',
            'DELETE_IN_PROGRESS',
        ]

    def get_compliance_type(self, compliance_result):
        return compliance_result['ComplianceType']

    def get_evaluation_timestamp(self, compliance_result):
        return compliance_result['ResultRecordedTime'].strftime('%d/%m/%Y %H:%M:%S')

    def get_rule_name(self, compliance_result):
        identifier = compliance_result['EvaluationResultIdentifier']
        qualifier = identifier['EvaluationResultQualifier']
        return qualifier['ConfigRuleName']

    def get_lambda_resource_id(self, function):
        return 'arn:aws:lambda:{region}:{account_id}:function:{function}'.format(
            region=self.account.region,
            account_id=self.account.id,
            function=function,
        )

    def get_rds_resource_id(self, db_identifier):
        client = self.account.get_client('rds')
        try:
            response = client.describe_db_instances(
                DBInstanceIdentifier=db_identifier
            )
        except ClientError as e:
            # This database might have been deleted outside CloudFormation
            if e.response['Error']['Code'] == 'DBInstanceNotFound':
                return None
            else:
                raise e

        return response['DBInstances'][0]['DbiResourceId']

    def get_compliance_results(self, resource):
        resource_type = self.get_resource_type(resource)
        resource_id = self.get_resource_id(resource)

        if resource_type == 'AWS::Lambda::Function':
            resource_id = self.get_lambda_resource_id(resource_id)

        elif resource_type == 'AWS::RDS::DBInstance':
            resource_id = self.get_rds_resource_id(resource_id)

        elif resource_type == 'AWS::Route53::RecordSet':
            resource_id = '{}.'.format(resource_id) if not resource_id.endswith('.') else resource_id

        if resource_id is None:
            return []

        client = self.account.get_client('config')
        paginator = client.get_paginator('get_compliance_details_by_resource')
        response_iterator = paginator.paginate(
            ResourceType=resource_type,
            ResourceId=resource_id,
        )

        return [
            evaluation_result
            for response in response_iterator
            for evaluation_result in response['EvaluationResults']
        ]

    def get_ec2_resources(self, autoscaling_group):
        client = self.account.get_client('autoscaling')
        response = client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group['PhysicalResourceId']]
        )

        return [
            {
                'ResourceType': 'AWS::EC2::Instance',
                'PhysicalResourceId': instance['InstanceId'],
                'ResourceStatus': 'CREATE_COMPLETE',
            }
            for autoscaling_group in response['AutoScalingGroups']
            for instance in autoscaling_group['Instances']
        ]

    def get_resources(self, stack):
        client = self.account.get_client('cloudformation')
        response = client.describe_stack_resources(
            StackName=self.get_stack_name(stack),
        )

        resources = response['StackResources']

        for resource in resources:
            if self.does_resource_exist(resource) and \
               self.get_resource_type(resource) == 'AWS::AutoScaling::AutoScalingGroup':
                resources += self.get_ec2_resources(resource)

        resources += [
            {
                'ResourceType': 'AWS::CloudFormation::Stack',
                'PhysicalResourceId': self.get_stack_name(stack),
                'ResourceStatus': 'CREATE_COMPLETE',
            }
        ]

        return resources

    def get_stacks(self):
        client = self.account.get_client('cloudformation')
        paginator = client.get_paginator('describe_stacks')
        response_iterator = paginator.paginate()
        return [stack
                for response in response_iterator
                for stack in response['Stacks']]

    def get_results(self):
        return [
            {
                'evaluation_time': self.get_evaluation_timestamp(compliance_result),
                'stack_id': self.get_stack_id(stack),
                'stack_name': self.get_stack_name(stack),
                'resource_type': self.get_resource_type(resource),
                'resource_id': self.get_resource_id(resource),
                'rule_name': self.get_rule_name(compliance_result),
                'compliance_type': self.get_compliance_type(compliance_result),
            }
            for stack in self.get_stacks()
            for resource in self.get_resources(stack)
            if self.does_resource_exist(resource)
            for compliance_result in self.get_compliance_results(resource)
        ]


if __name__ == '__main__':
    s3_client = Account().get_client('s3')
    account_ids = get_account_ids()

    for account_id in account_ids:
        account = Account(account_id, 'aab-compliance-report-role')
        report = ResourceComplianceReport(account)
        results = report.get_results()

        now = datetime.now()
        report_time = now.strftime('%d/%m/%Y %H:%M:%S')

        results = [
            {
                'report_time': report_time,
                'account_id': account.id,
                'account_alias': account.alias,
                'region': account.region,
                'evaluation_time': result['evaluation_time'],
                'stack_id': result['stack_id'],
                'stack_name': result['stack_name'],
                'resource_type': result['resource_type'],
                'resource_id': result['resource_id'],
                'rule_name': result['rule_name'],
                'compliance_type': result['compliance_type'],
            }
            for result in results
        ]

        print('Writing report for %s to logging bucket' % account_id)

        key = 'resource-compliance/{account_id}/{region}/{year}/{month}/{day}/report-{suffix}.json'.format(
            account_id=account.id,
            region=account.region,
            year=now.year,
            month=now.month,
            day=now.day,
            suffix=now.strftime('%H%M%S')
        )
        s3_client.put_object(
            ACL='bucket-owner-read',
            Body=json.dumps(results),
            Bucket='aab-compliance-reports',
            Key=key,
            ServerSideEncryption='AES256',
        )