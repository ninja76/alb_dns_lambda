import os
import datetime
import logging
import boto3
import json
import time
from botocore.vendored import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

zoneId = os.environ(ZONE_ID, None) #Route 53 Zone ID
iam_cross_account_arn = os.environ(IAM_CROSS_ACCOUNT_ARN, None) #Cross Account IAM role with permissions to Route53 zoneId
s3_r53_backup_bucket = os.environ(BUCKET, None) # Bucket where to dump zone backup before making changes

sts_client = boto3.client('sts')
watchedEvents = ['CreateLoadBalancer', 'DeleteLoadBalancer', 'AddTags', 'CreateDomainName', 'DeleteDomainName']

""" Setup Network Cross Account Access """
network_credentials = assumed_role_object=sts_client.assume_role(
    RoleArn=iam_cross_account_arn,
    RoleSessionName="ALB_HANDLER_ROUTE53"
)['Credentials']

r53Client = boto3.client(
    'route53',
    aws_access_key_id=network_credentials['AccessKeyId'],
    aws_secret_access_key=network_credentials['SecretAccessKey'],
    aws_session_token=network_credentials['SessionToken']
)

def run(event, context):
    ec2 = boto3.resource('ec2')
    dnsValue = None
    accountId = None
    albArn = None
    tags = {}
    hostnames = []
    # If AddTags event is detected then DO NOT delete anything as Added tag might not be dns
    #addTags = False
    eventName = event['detail']['eventName']

    if eventName in watchedEvents:
        print("DEBUG: {}".format(eventName))

        print(json.dumps(event))
        #Get Current records..
        currentRecords = r53Client.list_resource_record_sets(
            HostedZoneId = zoneId
        )

        accountId = event['detail']['userIdentity']['accountId']
        tags = event['detail']['requestParameters'].get('tags')

        if eventName == 'CreateLoadBalancer':
            albArn = event['detail']['responseElements']['loadBalancers'][0]['loadBalancerArn']
            dnsValue = event['detail']['responseElements']['loadBalancers'][0]['dNSName']

        elif eventName == 'DeleteLoadBalancer':
            print(event['detail']['requestParameters'])
            albArn = event['detail']['requestParameters']['loadBalancerArn']

        elif eventName == 'CreateDomainName':
            dnsValue = event['detail']['responseElements']['domainNameConfigurations'][0]['apiGatewayDomainName']
            hostnames.append(event['detail']['responseElements']['domainName'])

        elif eventName == 'AddTags':
            print("Addtags Event, I think... {}".format(eventName))
            albArn = event['detail']['requestParameters']['resourceArns'][0]

        elif eventName == 'DeleteDomainName':
            print("DeleteDomainName event.  Look up dnsValue...")
            hostnames.append(event['detail']['requestParameters']['domainName'])
            for rec in currentRecords['ResourceRecordSets']:
                if rec['Name'][:-1] == hostnames[0]:
                    print(rec['ResourceRecords'][0]['Value'])
                    dnsValue = rec['ResourceRecords'][0]['Value']
                    #print("Found dnsValue {}".format(dnsValue))

        if eventName != 'DeleteDomainName' and dnsValue == None:
            print("Looking up ALB {} {}".format(albArn, accountId))
            creds = getCreds(accountId)
            albClient = boto3.client(
                'elbv2',
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            dnsValue = getAlbDnsName(albArn, albClient)

        backupZone()

        if tags != {} and tags != None:
            print(tags)
            for t in tags:
                if t['key'] == 'dns':
                    hostnames = t['value'].split(' ')

        if hostnames == []:
            print("Found the Following hosts")
            print(hostnames)

        if eventName == 'CreateLoadBalancer' or eventName == 'CreateDomainName' or eventName == 'AddTags':
            for host in hostnames:
                exists = False
                for rec in currentRecords['ResourceRecordSets']:
                    if rec['Name'][:-1] == host:
                        exists = True
                if exists == False:
                    createRecord(host, dnsValue)

            for rec in currentRecords['ResourceRecordSets']:
                if rec['Type'] == 'CNAME' and rec['ResourceRecords'][0]['Value'] == dnsValue:
                    exists = False
                    for host in hostnames:
                        if rec['Name'][:-1] == host:
                            exists = True
                    if exists == False and eventName != 'AddTags':
                        deleteRecord(rec['Name'][:-1], dnsValue)

        elif eventName == 'DeleteDomainName' or eventName == 'DeleteLoadBalancer':
            for rec in currentRecords['ResourceRecordSets']:
                if rec['Type'] == 'CNAME' and rec['ResourceRecords'][0]['Value'] == dnsValue:
                    deleteRecord(rec['Name'][:-1], dnsValue)

def getAlbDnsName(arn, albClient):
    response = albClient.describe_load_balancers(
        LoadBalancerArns=[
            arn
        ])

    DNSName = response ['LoadBalancers'][0]['DNSName']
    #print("Found DNSName for {} {}".format(arn, response['LoadBalancers'][0]['DNSName']))
    return DNSName

def backupZone():
    print("Backing up zone to s3");
    currentRecords = r53Client.list_resource_record_sets(
            HostedZoneId = zoneId
    )

    s3 = boto3.resource('s3')
    s3object = s3.Object(s3_r53_backup_bucket, time.strftime("%Y%m%d-%H%M%S"))
    print(json.dumps(currentRecords))
    s3object.put(
        Body=(bytes(json.dumps(currentRecords).encode('UTF-8'))),
        ACL="bucket-owner-full-control"
    )

def updateRecord(source, target):
    print("Updating Record: []".format(hostnames))

def deleteRecord(source, target):
    print("Deleting Record: {} {}".format(source, target))

    response = r53Client.change_resource_record_sets(
        HostedZoneId = zoneId,
        ChangeBatch = {
            'Changes': [{
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': source,
                    'Type': 'CNAME',
                    'TTL': 300,
                    'ResourceRecords': [{'Value': target}]
                }
            }]
        }
    )

def createRecord(source, target):
    print("Creating Record: {} {}".format(source, target))

    response = r53Client.change_resource_record_sets(
        HostedZoneId = zoneId,
        ChangeBatch = {
            'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': source,
                        'Type': 'CNAME',
                        'TTL': 300,
                        'ResourceRecords': [{'Value': target}]
                    }
            }]
        }
    )

def getCreds(accountId):
    assumed_role_object=sts_client.assume_role(
        RoleArn=iam_cross_account_arn,
        RoleSessionName="ALB_HANDLER"
    )

    return assumed_role_object['Credentials']

if __name__ == "__main__":
    run(None, None)
