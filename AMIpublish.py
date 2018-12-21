#!/usr/bin/env python
"""
Publishes AMI release to SNS topics
"""

from __future__ import print_function

from botocore.client import Config
from boto3.session import Session
import json
import boto3
import os
import os.path
import json
import boto3
import zipfile

# For Production
boto = boto3

# For testing
# boto = boto3.Session(profile_name='eng1')

sns = boto.client('sns')

def tag_images(new_image_id, tags):
    """
    Maintain AMI tagging so that only the latest 3 AMI's are
    advertised as compliant
    """
    ec2_client = boto.client('ec2')

    ami_name_prefix = os.environ['AMI_NAME_PREFIX']
    old_amis = ec2_client.describe_images(
        Filters=[
            {
                'Name': 'state',
                'Values': ['available']
            },
            {
                'Name': 'tag-key',
                'Values': ['Version']
            },
            {
                'Name': 'name',
                'Values': ['{}-*'.format(ami_name_prefix)]
            }
        ],
        Owners=['self'],
    )
    # Re-tag the former 3 AMI's
    if any([
            old_ami['Name'].startswith(ami_name_prefix)
            for old_ami in old_amis['Images']
    ]):
        for old_ami in old_amis['Images']:
            if old_ami['Name'].startswith(ami_name_prefix):
                ami_id = old_ami['ImageId']
                if old_ami.get('Tags'):
                    for Tag in old_ami['Tags']:
                        if Tag['Key'] == 'Version' and Tag['Value'] == 'Latest-2':
                            ec2_client.create_tags(
                                Resources=[ami_id],
                                Tags=[
                                    {
                                        'Key': 'Version',
                                        'Value': 'NON_COMPLIANT'
                                    },
                                ])
                            print('Retagged Latest-2 to NON_COMPLIANT')
                            break
                        elif Tag['Key'] == 'Version' and Tag['Value'] == 'Latest-1':
                            ec2_client.create_tags(
                                Resources=[ami_id],
                                Tags=[
                                    {
                                        'Key': 'Version',
                                        'Value': 'Latest-2'
                                    },
                                ])
                            print('Retagged Latest-1 to Latest-2')
                            break
                        elif Tag['Key'] == 'Version' and Tag['Value'] == 'Latest':
                            ec2_client.create_tags(
                                Resources=[ami_id],
                                Tags=[
                                    {
                                        'Key': 'Version',
                                        'Value': 'Latest-1'
                                    },
                                ])
                            print('Retagged Latest to Latest-1')
                            break
                        else:
                            pass
    else:
        print('No former AMIs found, so moving on..')

    # Tag the latest AMI
    new_tags = {'Key': 'Version', 'Value': 'Latest'}
    tags.append(new_tags)
    ec2_client.create_tags(Resources=[new_image_id], Tags=tags)


def assemble_sns_message(name, image_id, region):
    return json.dumps(
        {
            'EC2Amis': [{
                'ReleaseVersion': 'Latest',
                'ReleaseNotes': 'CBSP hardened CentOS AMI.',
                'OsType': 'linux',
                'OperatingSystemName': 'CentOS',
                'Regions': {
                    region: {
                        'Name': name,
                        'ImageId': image_id
                    },
                }
            }]
        },
        indent=4,
        sort_keys=False)


def publish_to_sns(topic_arn, message):
    print("Message to publish: %s" % message)
    client = boto.client('sns')
    client.publish(
        TopicArn=topic_arn,
        MessageStructure='json',
        Message=json.dumps({
            'default': json.dumps(message)
        })
    )


def load_manifest_file():
    with open("manifest.json") as f:
        data = json.load(f)
        return data


def get_ami_details(ami_id):
    client = boto.client('ec2')
    response = client.describe_images(
        ImageIds=[
            ami_id
        ]
    )
    if 'Images' in response:
        if type(response['Images']) == list and len(response['Images']) > 0:
            if 'Name' in response['Images'][0]:
                ami_details = response['Images'][0]
                ami_details['CleanName'] = ami_details['Name'].replace(
                    '-flex', '')
                print('Ami Details: %s' % ami_details)
                return ami_details

    return None


def process_manifest(sns_topic, ssm_parameter, manifest_data):
    if 'builds' in manifest_data:
        if type(manifest_data['builds']) == list:
            # Indeed a list.
            for each_build in manifest_data['builds']:
                if 'artifact_id' in each_build:
                    region, ami_id = each_build['artifact_id'].split(':')
                    ami = get_ami_details(ami_id)
                    print ('AMI Details: %s' % ami)
                    ami_name = ami['CleanName']
                    ami_tags = ami['Tags']
                    print("AMI Region: %s" % region)
                    print("AMI ID: %s" % ami_id)
                    print("AMI Name: %s" % ami_name)
                    tag_images(new_image_id=ami_id,tags=ami_tags)
                    publish_to_sns(sns_topic, assemble_sns_message(ami_name, ami_id, region))
                    update_ssm_parameter(ssm_parameter, ami_id)

def update_ssm_parameter(ssm_parameter, ami_id):
    client = boto3.client('ssm')
    response = client.put_parameter(
        Name=ssm_parameter,
        Value=ami_id,
        Type='String',
        Overwrite=True
    )

def main():
    publish_sns_topic = os.environ.get('PUBLISH_SNS_TOPIC')
    latest_ami_ssm_parameter = os.environ.get('LATEST_AMI_SSM_PARAMETER')
    manifest_data = load_manifest_file()
    process_manifest(publish_sns_topic, latest_ami_ssm_parameter, manifest_data)


if __name__ == '__main__':
    main()
