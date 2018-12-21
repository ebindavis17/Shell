import boto3
from botocore.exceptions import ClientError
import functools
import json
import re
from common import Account, memoize, profile, get_account_ids
from datetime import datetime
import io
import os

TAG_APPLICATION_CI = 'Business Application CI'
TAG_BLOCK_ID = 'Block ID'
TAG_LAST_CHANGE = 'Last Change'
TAG_STACK_ID = 'aws:cloudformation:stack-id'
TAG_STACK_NAME = 'aws:cloudformation:stack-name'

RESOURCE_TYPES = [
    'AWS::EC2::Instance',
    'AWS::RDS::DBInstance',
    'AWS::CloudFront::Distribution',
    'AWS::ElasticLoadBalancing::LoadBalancer',
    'AWS::ElasticLoadBalancingV2::LoadBalancer',
    'AWS::S3::Bucket',
    'AWS::ApiGateway::RestApi',
    'AWS::Elasticsearch::Domain',
    'AWS::Redshift::Cluster',
    'AWS::EFS::FileSystem',
    'AWS::SNS::Topic',
    'AWS::SQS::Queue',
    'AWS::ECR::Repository',
]

ACCOUNT_IDS = get_account_ids()
ARN_REGEX = r'^arn:aws:(?P<service_name>.*?):(?P<region>.*?):(?P<account_id>[0-9]+?):'

class PublicEndpointReport:

    def __init__(self, account):
        self.account = account

        self.resources = {}
        self.add_all_cloudformation_resources()

    def does_resource_exist(self, resource):
        return resource['ResourceStatus'] not in [
            'CREATE_IN_PROGRESS',
            'CREATE_FAILED',
            'DELETE_COMPLETE',
            'DELETE_IN_PROGRESS',
        ]

    @memoize
    def is_public_subnet(self, subnet, region):
        client = self.account.get_client('ec2', region)
        subnet = client.describe_subnets(SubnetIds=[subnet])
        try:
            tags = subnet['Subnets'][0]['Tags']
        except KeyError:
            return True

        name = next(tag['Value'] for tag in tags if tag['Key'] == 'Name')

        return not name.startswith('Private')

    def get_ec2_resources(self, autoscaling_group):
        # TODO: multiple regions
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

    def get_all_recources(self, stack_name):
        client = self.account.get_client('cloudformation')
        response = client.describe_stack_resources(
            StackName=stack_name,
        )

        resources = response['StackResources']

        for resource in resources:
            if self.does_resource_exist(resource) and \
               resource['ResourceType'] == 'AWS::AutoScaling::AutoScalingGroup':
                resources += self.get_ec2_resources(resource)

        return resources

    def add_cloudformation_resource(self, stack, resource):
        if not self.does_resource_exist(resource):
            return

        # Catch rare cases where there is no ID or maybe even type to be found
        try:
            resource_type = resource['ResourceType']
            resource_id = resource['PhysicalResourceId']
        except KeyError:
            return

        if resource_type not in RESOURCE_TYPES:
            return

        if resource_type not in self.resources:
            self.resources[resource_type] = {}

        self.resources[resource_type][resource_id] = {
            'stack_id': stack['StackId'],
            'stack_name': stack['StackName'],
            'business_application_ci': self.get_tag(stack['Tags'], TAG_APPLICATION_CI),
            'block_id': self.get_tag(stack['Tags'], TAG_BLOCK_ID),
            'last_change': self.get_tag(stack['Tags'], TAG_LAST_CHANGE),
        }

    @profile
    def add_all_cloudformation_resources(self):
        # Only eu-west-1 right now (Improve this later)
        client = self.account.get_client('cloudformation')
        paginator = client.get_paginator('describe_stacks')
        response_iterator = paginator.paginate()

        for response in response_iterator:
            for stack in response['Stacks']:
                for resource in self.get_all_recources(stack['StackName']):
                    self.add_cloudformation_resource(stack, resource)

    def get_tag(self, tags, tag_name):
        for tag in tags:
            if tag['Key'] == tag_name:
                return tag['Value']
        return ''

    def does_principal_allow_public_access(self, principal):
        if principal == '*':
            return True
        elif 'AWS' in principal:
            accounts = principal['AWS']
            accounts = accounts if type(accounts) is list else [accounts]
            for account in accounts:
                match = re.match(ARN_REGEX, account)
                if not match or match.group('account_id') not in ACCOUNT_IDS:
                    return True

        return False

    def does_condition_allow_public_access(self, condition):
        operators = [
            'StringEquals',
            'StringEqualsIgnoreCase',
            'StringLike',
            'ArnEquals',
            'ArnLike',
        ]

        for operator in operators:
            if operator in condition:
                if 'AWS:SourceOwner' in condition[operator]:
                    account_ids = condition[operator]['AWS:SourceOwner']
                    account_ids = account_ids if type(account_ids) is list else [account_ids]

                    for id in account_ids:
                        if id not in ACCOUNT_IDS:
                            # Explicitly allowing an account that is not us
                            return True

                    # Restricted to only our accounts
                    return False

                if 'aws:SourceArn' in condition[operator]:
                    account_arns = condition[operator]['aws:SourceArn']
                    account_arns = account_arns if type(account_arns) is list else [account_arns]

                    for account_arn in account_arns:
                        match = re.match(ARN_REGEX, account_arn)
                        if not match or match.group('account_id') not in ACCOUNT_IDS:
                            # Explicitly allowing an account that is not us
                            return True

                    # Restricted to only our accounts
                    return False

        # No restrictions
        return True

    def does_policy_allow_public_access(self, policy):
        for statement in policy['Statement']:
            if statement['Effect'] == 'Deny':
                continue

            principal = statement['Principal']
            condition = statement['Condition'] if 'Condition' in statement else {}

            if self.does_principal_allow_public_access(principal) \
                    and self.does_condition_allow_public_access(condition):
                return True

        return False

    def get_public_ec2_endpoint(self, instance, region):
        tags = instance.get('Tags', [])

        return {
            'resource_type': 'AWS::EC2::Instance',
            'region': region,
            'resource_id': instance['InstanceId'],
            'endpoint': next(eni['Association']['PublicIp']
                for eni in instance['NetworkInterfaces'] if 'Association' in eni),
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_ec2_endpoints_for_region(self, region):
        client = self.account.get_client('ec2', region)
        paginator = client.get_paginator('describe_instances')
        response_iterator = paginator.paginate(
            Filters=[
                {
                    'Name': 'network-interface.association.public-ip',
                    'Values': ['*']
                }
            ]
        )

        return [
            self.get_public_ec2_endpoint(instance, region)
            for response in response_iterator
            for reservation in response['Reservations']
            for instance in reservation['Instances']
        ]

    @profile
    def get_all_public_ec2_endpoints(self):
        regions = self.account.session.get_available_regions('ec2')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_ec2_endpoints_for_region(region)
        ]

    def get_public_ecs_endpoints(self, cluster_arn, service_arn, region):
        client = self.account.get_client('ecs', region)
        response = client.describe_services(
            cluster=cluster_arn,
            services=[service_arn]
        )

        return [
            {
                'resource_type': 'AWS::ECS::Service',
                'region': region,
                'resource_id': service_arn,
                'endpoint': '???',
                'business_application_ci': '',
                'block_id': '',
                'last_change': '',
                'stack_id': '',
                'stack_name': '',
            }
            for service in response['services']
            if service['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] == 'ENABLED'
        ]

    def get_all_public_ecs_services(self, cluster_arn, region):
        client = self.account.get_client('ecs', region)
        paginator = client.get_paginator('list_services')
        response_iterator = paginator.paginate(
            cluster=cluster_arn,
            launchType='FARGATE',
        )

        return [
            endpoint
            for response in response_iterator
            for service_arn in response['serviceArns']
            for endpoint in self.get_public_ecs_endpoints(cluster_arn, service_arn, region)
        ]

    def get_public_ecs_endpoints_for_region(self, region):
        client = self.account.get_client('ecs', region)
        paginator = client.get_paginator('list_clusters')
        response_iterator = paginator.paginate()

        return [
            public_endpoint
            for response in response_iterator
            for cluster_arn in response['clusterArns']
            for public_endpoint in self.get_all_public_ecs_services(cluster_arn, region)
        ]

    @profile
    def get_all_public_ecs_endpoints(self):
        regions = self.account.session.get_available_regions('ecs')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_ecs_endpoints_for_region(region)
        ]

    def get_rds_tags(self, resource_name, region):
        client = self.account.get_client('rds', region)
        response = client.list_tags_for_resource(
            ResourceName=resource_name,
        )
        return response['TagList']

    def get_public_rds_endpoint(self, instance, region):
        tags = self.get_rds_tags(instance['DBInstanceArn'], region)

        return {
            'resource_type': 'AWS::RDS::DBInstance',
            'region': region,
            'resource_id': instance['DBInstanceArn'],
            'endpoint': instance['Endpoint']['Address'],
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_rds_endpoints_for_region(self, region):
        client = self.account.get_client('rds', region)
        paginator = client.get_paginator('describe_db_instances')
        response_iterator = paginator.paginate()

        return [
            self.get_public_rds_endpoint(instance, region)
            for response in response_iterator
            for instance in response['DBInstances']
            if instance['PubliclyAccessible']
        ]

    @profile
    def get_all_public_rds_endpoints(self):
        regions = self.account.session.get_available_regions('rds')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_rds_endpoints_for_region(region)
        ]

    def get_cloudfront_tags(self, resource_name):
        client = self.account.get_client('cloudfront')
        response = client.list_tags_for_resource(
            Resource=resource_name
        )
        return response['Tags']['Items']

    def get_cloudfront_endpoint(self, distribution):
        tags = self.get_cloudfront_tags(distribution['ARN'])
        endpoint = (distribution['Aliases']['Items'][0]
            if distribution['Aliases']['Quantity'] > 0
            else distribution['DomainName']
        )

        return {
            'resource_type': 'AWS::CloudFront::Distribution',
            'region': 'GLOBAL',
            'resource_id': distribution['Id'],
            'endpoint': endpoint,
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    @profile
    def get_all_cloudfront_endpoints(self):
        client = self.account.get_client('cloudfront')
        paginator = client.get_paginator('list_distributions')
        response_iterator = paginator.paginate()

        return [
            self.get_cloudfront_endpoint(distribution)
            for response in response_iterator
            if response['DistributionList']['Quantity'] > 0
            for distribution in response['DistributionList']['Items']
        ]

    @profile
    def get_all_cloudfront_streaming_endpoints(self):
        client = self.account.get_client('cloudfront')
        paginator = client.get_paginator('list_streaming_distributions')
        response_iterator = paginator.paginate()

        return [
            self.get_cloudfront_endpoint(distribution)
            for response in response_iterator
            if response['StreamingDistributionList']['Quantity'] > 0
            for distribution in response['StreamingDistributionList']['Items']
        ]

    def get_elb_tags(self, load_balancer_name, region):
        client = self.account.get_client('elb', region)
        response = client.describe_tags(
            LoadBalancerNames=[load_balancer_name]
        )

        if len(response['TagDescriptions']) < 1:
            return []

        return response['TagDescriptions'][0]['Tags']

    def get_public_elb_endpoint(self, load_balancer, region):
        tags = self.get_elb_tags(load_balancer['LoadBalancerName'], region)

        return {
            'resource_type': 'AWS::ElasticLoadBalancing::LoadBalancer',
            'region': region,
            'resource_id': load_balancer['LoadBalancerName'],
            'endpoint': load_balancer['DNSName'],
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_elb_endpoints_for_region(self, region):
        client = self.account.get_client('elb', region)
        paginator = client.get_paginator('describe_load_balancers')
        response_iterator = paginator.paginate()

        return [
            self.get_public_elb_endpoint(load_balancer, region)
            for response in response_iterator
            for load_balancer in response['LoadBalancerDescriptions']
            if load_balancer['Scheme'] == 'internet-facing'
        ]

    @profile
    def get_all_public_elb_endpoints(self):
        regions = self.account.session.get_available_regions('elb')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_elb_endpoints_for_region(region)
        ]

    def get_alb_tags(self, load_balancer_arn, region):
        client = self.account.get_client('elbv2', region)
        response = client.describe_tags(
            ResourceArns=[load_balancer_arn]
        )

        if len(response['TagDescriptions']) < 1:
            return []

        return response['TagDescriptions'][0]['Tags']

    def get_public_alb_endpoint(self, load_balancer, region):
        tags = self.get_alb_tags(load_balancer['LoadBalancerArn'], region)

        return {
            'resource_type': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
            'region': region,
            'resource_id': load_balancer['LoadBalancerArn'],
            'endpoint': load_balancer['DNSName'],
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_alb_endpoints_for_region(self, region):
        client = self.account.get_client('elbv2', region)
        paginator = client.get_paginator('describe_load_balancers')
        response_iterator = paginator.paginate()

        return [
            self.get_public_alb_endpoint(load_balancer, region)
            for response in response_iterator
            for load_balancer in response['LoadBalancers']
            if load_balancer['Scheme'] == 'internet-facing'
        ]

    @profile
    def get_all_public_alb_endpoints(self):
        regions = self.account.session.get_available_regions('elbv2')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_alb_endpoints_for_region(region)
        ]

    def does_bucket_allow_public_access(self, bucket_name):
        client = self.account.get_client('s3')
        try:
            response = client.get_bucket_acl(
                Bucket=bucket_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                # We can not verify whether it is private or public, so assume the worst
                return True
            elif e.response['Error']['Code'] == 'NoSuchBucket':
                print('Bucket %s does not exist' % bucket_name)
                return False
            else:
                raise e

        for grant in response['Grants']:
            if 'URI' in grant['Grantee'] and \
               re.search(r'global/(AllUsers|AuthenticatedUsers)$', grant['Grantee']['URI']):
                return True

        return False

    def get_s3_tags(self, bucket_name):
        client = self.account.get_client('s3')
        try:
            response = client.get_bucket_tagging(
                Bucket=bucket_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                return []
            elif e.response['Error']['Code'] == 'NoSuchTagSet':
                return []
            else:
                raise e

        return response['TagSet']

    def get_s3_location(self, bucket_name):
        client = self.account.get_client('s3')
        try:
            response = client.get_bucket_location(
                Bucket=bucket_name
            )
        except ClientError as e:
            # No access, so most likely region is eu-west-1
            if e.response['Error']['Code'] == 'AccessDenied':
                return 'eu-west-1'
            else:
                raise e

        # No contraints, so us-east-1?
        if not response['LocationConstraint']:
            return 'us-east-1'

        return response['LocationConstraint']

    def get_public_s3_endpoint(self, bucket_name):
        tags = self.get_s3_tags(bucket_name)
        region = self.get_s3_location(bucket_name)

        return {
            'resource_type': 'AWS::S3::Bucket',
            'region': region,
            'resource_id': bucket_name,
            'endpoint': '{}.s3-{}.amazonaws.com'.format(bucket_name, region),
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    @profile
    def get_all_public_s3_endpoints(self):
        client = self.account.get_client('s3')
        response = client.list_buckets()
        return [
            self.get_public_s3_endpoint(bucket['Name'])
            for bucket in response['Buckets']
            if self.does_bucket_allow_public_access(bucket['Name'])
        ]

    def get_public_apigateway_endpoint(self, api, region):
        return {
            'resource_type': 'AWS::ApiGateway::RestApi',
            'region': region,
            'resource_id': api['id'],
            'endpoint': ('%s.execute-api.eu-west-1.amazonaws.com' % api['id']),
            'business_application_ci': '', # No tags possible
            'block_id': '', # No tags possible
            'last_change': '', # No tags possible
            'stack_id': '', # No tags possible
            'stack_name': '', # No tags possible
        }

    def get_public_apigateway_endpoints_for_region(self, region):
        client = self.account.get_client('apigateway', region)
        paginator = client.get_paginator('get_rest_apis')
        response_iterator = paginator.paginate()

        return [
            self.get_public_apigateway_endpoint(api, region)
            for response in response_iterator
            for api in response['items']
            if len(api['endpointConfiguration']['types']) > 1 or
                api['endpointConfiguration']['types'][0] != 'PRIVATE'
        ]

    @profile
    def get_all_public_apigateway_endpoints(self):
        regions = self.account.session.get_available_regions('apigateway')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_apigateway_endpoints_for_region(region)
        ]

    def get_es_domain_details(self, domain_name, region):
        client = self.account.get_client('es', region)
        response = client.describe_elasticsearch_domains(
            DomainNames=[domain_name]
        )
        return response['DomainStatusList']

    def get_es_tags(self, es_arn, region):
        client = self.account.get_client('es', region)
        response = client.list_tags(
            ARN=es_arn
        )

        return response['TagList']

    def get_public_es_endpoint(self, details, region):
        tags = self.get_es_tags(details['ARN'], region)

        return {
            'resource_type': 'AWS::Elasticsearch::Domain',
            'region': region,
            'resource_id': details['ARN'],
            'endpoint': details['Endpoint'] if 'Endpoint' in details else '',
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_es_endpoints_for_region(self, region):
        client = self.account.get_client('es', region)
        response = client.list_domain_names()

        # Criteria: No VPC or in VPC public subnet
        return [
            self.get_public_es_endpoint(details, region)
            for domain in response['DomainNames']
            for details in self.get_es_domain_details(domain['DomainName'], region)
            if ('VPCOptions' not in details or \
                any(self.is_public_subnet(subnet, region) for subnet in details['VPCOptions']['SubnetIds'])
            )
        ]

    @profile
    def get_all_public_es_endpoints(self):
        regions = self.account.session.get_available_regions('es')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_es_endpoints_for_region(region)
        ]

    def get_public_redshift_endpoint(self, redshift_cluster, region):
        tags = redshift_cluster['Tags']

        return {
            'resource_type': 'AWS::Redshift::Cluster',
            'region': region,
            'resource_id': redshift_cluster['ClusterIdentifier'],
            'endpoint': redshift_cluster['Endpoint']['Address'],
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_public_redshift_endpoints_for_region(self, region):
        client = self.account.get_client('redshift', region)
        paginator = client.get_paginator('describe_clusters')
        response_iterator = paginator.paginate()

        return [
            self.get_public_redshift_endpoint(redshift_cluster, region)
            for response in response_iterator
            for redshift_cluster in response['Clusters']
            if redshift_cluster['PubliclyAccessible']
        ]

    @profile
    def get_all_public_redshift_endpoints(self):
        regions = self.account.session.get_available_regions('redshift')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_redshift_endpoints_for_region(region)
        ]

    def get_public_efs_endpoint(self, file_system, mount_target, region):
        client = self.account.get_client('efs', region)
        response = client.describe_tags(
            FileSystemId=file_system['FileSystemId']
        )
        tags = response['Tags']

        return {
            'resource_type': 'AWS::EFS::FileSystem',
            'region': region,
            'resource_id': file_system['FileSystemId'],
            'endpoint': mount_target['IpAddress'],
            'business_application_ci': self.get_tag(tags, TAG_APPLICATION_CI),
            'block_id': self.get_tag(tags, TAG_BLOCK_ID),
            'last_change': self.get_tag(tags, TAG_LAST_CHANGE),
            'stack_id': self.get_tag(tags, TAG_STACK_ID),
            'stack_name': self.get_tag(tags, TAG_STACK_NAME),
        }

    def get_mount_targets_for_file_system(self, file_system, region):
        client = self.account.get_client('efs', region)
        paginator = client.get_paginator('describe_mount_targets')
        response_iterator = paginator.paginate(
            FileSystemId=file_system['FileSystemId'],
        )

        return [
            mount_target
            for response in response_iterator
            for mount_target in response['MountTargets']
        ]

    def get_public_efs_endpoints_for_region(self, region):
        client = self.account.get_client('efs', region)
        paginator = client.get_paginator('describe_file_systems')
        response_iterator = paginator.paginate()

        return [
            self.get_public_efs_endpoint(file_system, mount_target, region)
            for response in response_iterator
            for file_system in response['FileSystems']
            for mount_target in self.get_mount_targets_for_file_system(file_system, region)
            if self.is_public_subnet(mount_target['SubnetId'], region)
        ]

    @profile
    def get_all_public_efs_endpoints(self):
        regions = self.account.session.get_available_regions('efs')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_efs_endpoints_for_region(region)
        ]

    def is_public_ecr(self, repository, region):
        client = self.account.get_client('ecr', region)
        try:
            response = client.get_repository_policy(
                repositoryName=repository['repositoryName']
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'RepositoryPolicyNotFoundException':
                return False
            elif e.response['Error']['Code'] == 'AccessDeniedException':
                # Can not get policy so assume worst case
                return True
            else:
                raise e

        policy = json.loads(response['policyText'])

        return self.does_policy_allow_public_access(policy)

    def get_public_ecr_endpoint(self, repository, region):
        return {
            'resource_type': 'AWS::ECR::Repository',
            'region': region,
            'resource_id': repository['repositoryName'],
            'endpoint': repository['repositoryUri'],
            'business_application_ci': '',
            'block_id': '',
            'last_change': '',
            'stack_id': '',
            'stack_name': '',
        }

    def get_public_ecr_endpoints_for_region(self, region):
        client = self.account.get_client('ecr', region)
        paginator = client.get_paginator('describe_repositories')
        response_iterator = paginator.paginate()

        return [
            self.get_public_ecr_endpoint(repository, region)
            for response in response_iterator
            for repository in response['repositories']
            if self.is_public_ecr(repository, region)
        ]

    @profile
    def get_all_public_ecr_endpoints(self):
        regions = self.account.session.get_available_regions('ecr')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_ecr_endpoints_for_region(region)
        ]

    def is_public_sns(self, topic, region):
        client = self.account.get_client('sns', region)
        response = client.get_topic_attributes(
            TopicArn=topic['TopicArn'],
        )

        if 'Policy' not in response['Attributes']:
            return False

        policy = json.loads(response['Attributes']['Policy'])

        return self.does_policy_allow_public_access(policy)

    def get_public_sns_endpoint(self, topic, region):
        # No tags for SNS
        return {
            'resource_type': 'AWS::SNS::Topic',
            'region': region,
            'resource_id': topic['TopicArn'],
            'endpoint': 'sns.{}.amazonaws.com/?TopicArn={}'.format(region, topic['TopicArn']),
            'business_application_ci': '',
            'block_id': '',
            'last_change': '',
            'stack_id': '',
            'stack_name': '',
        }

    def get_public_sns_endpoints_for_region(self, region):
        client = self.account.get_client('sns', region)
        paginator = client.get_paginator('list_topics')
        response_iterator = paginator.paginate()

        return [
            self.get_public_sns_endpoint(topic, region)
            for response in response_iterator
            for topic in response['Topics']
            if self.is_public_sns(topic, region)
        ]

    @profile
    def get_all_public_sns_endpoints(self):
        regions = self.account.session.get_available_regions('sns')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_sns_endpoints_for_region(region)
        ]

    def is_public_sqs(self, queue_url, region):
        client = self.account.get_client('sqs', region)
        response = client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['Policy']
        )

        if 'Attributes' not in response:
            return False

        policy = json.loads(response['Attributes']['Policy'])

        return self.does_policy_allow_public_access(policy)

    def get_public_sqs_endpoint(self, queue_url, region):
        # No tags for SNS
        return {
            'resource_type': 'AWS::SQS::Queue',
            'region': region,
            'resource_id': queue_url,
            'endpoint': queue_url,
            'business_application_ci': '',
            'block_id': '',
            'last_change': '',
            'stack_id': '',
            'stack_name': '',
        }

    def get_public_sqs_endpoints_for_region(self, region):
        client = self.account.get_client('sqs', region)
        response = client.list_queues() # up to a 1000 queues

        if 'QueueUrls' not in response:
            return []

        return [
            self.get_public_sqs_endpoint(queue, region)
            for queue in response['QueueUrls']
            if self.is_public_sqs(queue, region)
        ]

    @profile
    def get_all_public_sqs_endpoints(self):
        regions = self.account.session.get_available_regions('sqs')

        return [
            endpoint
            for region in regions
            for endpoint in self.get_public_sqs_endpoints_for_region(region)
        ]

    def get_all_public_endpoints(self):
        endpoints = []

        endpoints += self.get_all_public_ec2_endpoints()
        endpoints += self.get_all_public_ecs_endpoints()
        endpoints += self.get_all_public_rds_endpoints()
        endpoints += self.get_all_cloudfront_endpoints()
        endpoints += self.get_all_cloudfront_streaming_endpoints()
        endpoints += self.get_all_public_elb_endpoints()
        endpoints += self.get_all_public_alb_endpoints()
        endpoints += self.get_all_public_s3_endpoints()
        endpoints += self.get_all_public_apigateway_endpoints()
        endpoints += self.get_all_public_es_endpoints()
        endpoints += self.get_all_public_redshift_endpoints()
        endpoints += self.get_all_public_efs_endpoints()
        endpoints += self.get_all_public_ecr_endpoints()
        endpoints += self.get_all_public_sns_endpoints()
        endpoints += self.get_all_public_sqs_endpoints()
        # mq

        for endpoint in endpoints:
            if not endpoint['stack_id']:
                resource_type = endpoint['resource_type']
                resource_id = endpoint['resource_id']

                if resource_type in self.resources \
                   and resource_id in self.resources[resource_type]:
                    endpoint.update(self.resources[resource_type][resource_id])

        return endpoints


if __name__ == '__main__':
    account = Account()

    s3_client = account.get_client('s3')
    codebuild_client = account.get_client('codebuild')

    report = PublicEndpointReport(account)
    endpoints = report.get_all_public_endpoints()

    now = datetime.now()
    report_time = now.strftime('%d/%m/%Y %H:%M:%S')

    endpoints = [
        {
            'report_time': report_time,
            'account_id': account.id,
            'account_alias': account.alias,
            'region': endpoint['region'],
            'resource_type': endpoint['resource_type'],
            'resource_id': endpoint['resource_id'],
            'endpoint': endpoint['endpoint'],
            'business_application_ci': endpoint['business_application_ci'],
            'block_id': endpoint['block_id'],
            'last_change': endpoint['last_change'],
            'stack_id': endpoint['stack_id'],
            'stack_name': endpoint['stack_name'],
        }
        for endpoint in endpoints
    ]

    print('Writing report for %s to logging bucket' % account.id)

    key = 'public-endpoints/{account_id}/{region}/{year}/{month}/{day}/report-{suffix}.json'.format(
        account_id=account.id,
        region='eu-west-1',
        year=now.year,
        month=now.month,
        day=now.day,
        suffix=now.strftime('%H%M%S')
    )
    body = json.dumps(endpoints)

    # Write body to CludWatch logs by printing and save it in S3
    print(body)
    s3_client.put_object(
        GrantRead='id="e9535778c0acb3c857c159b3a011b763262abfad6769fe8f3386471a7befd3d1", id="219ad23f1414517c4ff242fa83475b9760a6770b0301973a95acfca63ffbcf81"',
        Body=json.dumps(endpoints),
        Bucket='aab-compliance-reports',
        Key=key,
        ServerSideEncryption='AES256',
    )
