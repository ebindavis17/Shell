import boto3
import json
import logging
from botocore.exceptions import ClientError


logging_level = 'INFO'
logger = logging.getLogger(__name__)
logger.setLevel(logging_level)


class S3Access(object):
    def __init__(self, bucket_name, create_bucket_request_params=None, bucket_policy=None, acl=None, obj=None):
        self.s3_resource = boto3.resource('s3')
        self.bucket = bucket_name
        self.policy = bucket_policy
        self.acl = acl
        self.object = obj
        self.create_bucket_request_params = create_bucket_request_params

    def check_request_params_and_sanitize(self):
        try:
            put_request_params = {}
            if 'x-amz-acl' in self.create_bucket_request_params:
                old_acl = self.create_bucket_request_params['x-amz-acl']
                for acl in old_acl:
                    if acl in ['public-read', 'public-read-write', 'authenticated-read']:
                        put_request_params['ACL'] = 'private'
                        logger.info('Bucket %s was created with a canned ACL %s. Will revert ACL to private.' %
                                    (self.bucket, acl))
                    else:
                        logger.info('Bucket %s was created with a canned ACL %s which is not public.' %
                                    (self.bucket, acl))
            else:
                acls = {
                    'x-amz-grant-read': 'GrantRead',
                    'x-amz-grant-write': 'GrantWrite',
                    'x-amz-grant-read-acp': 'GrantReadACP',
                    'x-amz-grant-write-acp': 'GrantWriteACP',
                    'x-amz-grant-full-control': 'GrantFullControl'
                }

                for acl in acls:
                    if acl in self.create_bucket_request_params:
                        old_grantees = self.create_bucket_request_params[acl]
                        old_grantee_list = []
                        new_grantee_list = []
                        for _ in old_grantees:
                            for grantee in _.split(','):
                                old_grantee_list.append(grantee)
                                if 'http://acs.amazonaws.com/groups/global/AllUsers' not in grantee and \
                                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' not in grantee:
                                    new_grantee_list.append(grantee)
                                else:
                                    logger.info('Bucket %s was created with ACL %s for %s. ACL marked for removal.' %
                                                (self.bucket, acl, grantee))
                        if len(new_grantee_list) < len(old_grantee_list):
                            new_grantee = ','.join(new_grantee_list)
                            logger.info('New grantee %s for ACL %s will be applied for bucket %s.' %
                                        (new_grantee, acl, self.bucket))
                            put_request_params[acls[acl]] = new_grantee
                        else:
                            logger.info('For ACL %s in bucket %s no grantee is public %s' %
                                        (acl, self.bucket, ','.join(old_grantee_list)))
            if put_request_params:
                s3_acl = self.s3_resource.BucketAcl(self.bucket)
                s3_acl.put(**put_request_params)
                logger.info('Bucket ACLs for %s reverted to: %s' % (self.bucket, str(put_request_params)))
            else:
                logger.info('Bucket was created with compliant ACLs')

        except ClientError as e:
            logger.error('The S3 bucket ACL remediation failed: ' + e.response['Error']['Message'])

    """The below method will check the bucket policy applied to the S3 bucket, and if any statement
    contains * as Principal, it will re-apply the bucket policy without that statement."""
    def check_policy_and_sanitize(self):
        try:
            policy_version = self.policy['Version']
            old_policy_statements = self.policy['Statement']
            new_policy_statements = [statement for statement in old_policy_statements if
                                     not (statement['Principal'] == '*' and statement['Effect'] == 'Allow')]
            s3_bucket_policy = self.s3_resource.BucketPolicy(self.bucket)
            if not new_policy_statements:
                s3_bucket_policy.delete()
                logger.info(' '.join(['The S3 bucket policy for bucket', self.bucket, 'was deleted.']))
            elif len(new_policy_statements) < len(old_policy_statements):
                new_policy = {
                    'Version': policy_version,
                    'Statement': new_policy_statements
                }
                new_policy_json = json.dumps(new_policy)
                s3_bucket_policy.put(Policy=new_policy_json)
                logger.info(' '.join(['The S3 bucket policy for bucket', self.bucket, 'was modified.']))
            else:
                logger.info(' '.join(['The S3 bucket policy statements for bucket', self.bucket, 'are compliant.']))
        except ClientError as e:
            logger.error('The S3 bucket policy remediation failed: ' + e.response['Error']['Message'])

    """The below method iterates through all the entries in a bucket or object ACL, and removes the
    entries that have as a Grantee AllUsers (everyone)."""
    def check_acl_and_sanitize(self):
        try:
            if self.acl['AccessControlList'] == "":
                logger.info(' '.join(['The ACL for bucket', self.bucket, 'and object', str(self.object), 'is empty.']))
            else:
                old_gr = self.acl['AccessControlList']['Grant']
                logger.debug(old_gr)
                if isinstance(old_gr, dict):
                    old_gr = [self.acl['AccessControlList']['Grant']]
                new_gr = []
                for gr in old_gr:
                    if not ((gr['Grantee']['xsi:type'] == 'Group' and
                                     gr['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers') or
                                (gr['Grantee']['xsi:type'] == 'Group' and
                                         gr['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers')):
                        try:
                            gr['Grantee']['ID']
                        except KeyError:
                            transformed_gr = {
                                'Grantee': {
                                    'Type': gr['Grantee']['xsi:type'],
                                    'URI': gr['Grantee']['URI']
                                },
                                'Permission': gr['Permission']
                            }
                        else:
                            transformed_gr = {
                                'Grantee': {
                                    'Type': gr['Grantee']['xsi:type'],
                                    'ID': gr['Grantee']['ID']
                                },
                                'Permission': gr['Permission']
                            }
                        finally:
                            new_gr.append(transformed_gr)

                if len(new_gr) < len(old_gr):
                    owner_id = self.acl['Owner']['ID']
                    try:
                        owner_name = self.acl['Owner']['DisplayName']
                    except KeyError:
                        new_acl = {
                            'Grants': new_gr,
                            'Owner': {
                                'ID': owner_id
                            }
                        }
                    else:
                        new_acl = {
                            'Grants': new_gr,
                            'Owner': {
                                'DisplayName': owner_name,
                                'ID': owner_id
                            }
                        }
                    if self.object is None:
                        s3_acl = self.s3_resource.BucketAcl(self.bucket)
                        s3_acl.put(AccessControlPolicy=new_acl)
                    else:
                        s3_acl = self.s3_resource.ObjectAcl(self.bucket, self.object)
                        s3_acl.put(AccessControlPolicy=new_acl)
                    logger.info(' '.join(['The ACL for bucket', self.bucket, 'and object',
                                          str(self.object), 'was modified.']))
        except ClientError as e:
            logger.error('The S3 bucket and object ACL remediation failed: ' + e.response['Error']['Message'])


def lambda_handler(event, context):
    logger.info('S3 Access remediation - version 1.0')
    logger.debug(event)
    """Check if the S3 API call returned an error, and if not, depending on which call was made, parse the input,
     instantiate the S3_access object, and use the desired method."""
    try:
        event['detail']['errorCode']
    except KeyError:
        """If KeyError exception is caught, it means that the API response does not contain the errorCode field,
            and we can continue with the function logic."""
        bucket = event['detail']['requestParameters']['bucketName']

        if event['detail']['eventName'] == 'CreateBucket':
            request_params = event['detail']['requestParameters']
            s3 = S3Access(bucket, create_bucket_request_params=request_params)
            s3.check_request_params_and_sanitize()
        elif event['detail']['eventName'] == 'PutBucketPolicy':
            bucket_policy = event['detail']['requestParameters']['bucketPolicy']
            s3 = S3Access(bucket, bucket_policy=bucket_policy)
            s3.check_policy_and_sanitize()

        elif event['detail']['eventName'] == 'PutBucketAcl':
            bucket_acl = event['detail']['requestParameters']['AccessControlPolicy']
            s3 = S3Access(bucket, acl=bucket_acl)
            s3.check_acl_and_sanitize()

        elif event['detail']['eventName'] == 'PutObjectAcl':
            object_acl = event['detail']['requestParameters']['AccessControlPolicy']
            object_key = event['detail']['requestParameters']['key']
            s3 = S3Access(bucket, acl=object_acl, obj=object_key)
            s3.check_acl_and_sanitize()
        else:
            logger.info('The API call made was: ' + event['detail']['eventName'])

    else:
        logger.info(' '.join(['The original S3 API call returned:', event['detail']['errorCode'],
                              'Check the received notification or CloudTrail logs for more details. S3 request ID:',
                              event['detail']['requestID']]))
