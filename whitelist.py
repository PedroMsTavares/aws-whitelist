import requests
import boto3
from botocore.exceptions import ClientError
import sys
import argparse
import os
from datetime import datetime
import json
client = boto3.client('ec2')

def getpublicip():
    ip = requests.get('http://ip.42.pl/raw').text
    return(ip + '/32')

def findSecurityGroups():
    try:
        secgroups=client.describe_security_groups()
    except ClientError as e:
        print(e)
    print ("Security Group Options:")
    i=0
    while i<len(secgroups['SecurityGroups']):
        print( str(i) +" - " +secgroups['SecurityGroups'][i]['Description']) 
        i+=1
    opt = None
    while type(opt) != int or int(opt) > i:
        opt = input("Please choose the security group to whitelist: ") 
        try:
            opt = int(opt)
        except:
            print('You did not enter a valid number')
    return (secgroups['SecurityGroups'][int(opt)]['GroupId'])

def ruleExists(ip, groupid):
    try:
         response = client.describe_security_groups(
             Filters=[
                    {
                        'Name': 'ip-permission.cidr',
                        'Values': [
                            ip,
                        ]
                    },
                    {
                        'Name': 'ip-permission.from-port',
                        'Values': [
                            '22',
                        ]
                    },
                    {
                        'Name': 'ip-permission.protocol',
                        'Values': [
                            'tcp',
                        ]
                    },
                ],
                GroupIds=[
                    groupid
                ]
            )
         if len(response['SecurityGroups']) > 0 :
             print('Your IP address has been whitelisted before')
             return True
         return False 
    except Exception as e:
        print(e)
    

def whitelist(ip , groupid):
    try:
        _ruleexists = ruleExists(ip,groupid)
        if _ruleexists == False:
            client.authorize_security_group_ingress(
                GroupId=groupid,
                IpPermissions = [
                    {'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [
                            {
                            'CidrIp': ip,
                            'Description': 'Temporary remote access rule added: ' + str(datetime.today())
                            }
                        ]
                    }
                    
                ])
            print("Your IP address has been whitelisted")
    except ClientError as e:
        print(e)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--aws_profile', help='Name of aws profile')
    parser.add_argument('--aws_region', help='Name of the aws region')

    args=parser.parse_args()

    if 'None' in str(args):
        print('Args missings. please run ' + __file__.split('/')[-1] + ' -h for help')
        exit(0)

    try:
        boto3.setup_default_session(profile_name=args.aws_profile)
        boto3.setup_default_session(region_name=args.aws_region)
    except :
        print ("Oops! there is something wrong with the profile")
        sys.exit()

    whitelist(getpublicip(), findSecurityGroups())


if __name__ == '__main__':
    main()