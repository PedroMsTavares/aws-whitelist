import requests
import boto3
from botocore.exceptions import ClientError
import sys




client = boto3.client('ec2')

def getpublicip():
    ip = requests.get('http://ip.42.pl/raw').text
    return(ip)

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
    opt = input("Please choose the security group to whitelist yourself : ") 
    while int(opt) > i :
        opt = input("Please choose the security group to whitelist yourself : ")
    return (secgroups['SecurityGroups'][int(opt)]['GroupId'])

def whitelist(ip , groupid):
    try:
     client.authorize_security_group_ingress(
        GroupId=groupid,
        IpPermissions = [
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': ip + '/32'}]}
            
        ])
     print("Your Ip is whitelisted")
    except ClientError as e:
        print(e)

def main():
    if len(sys.argv) > 1:
        try:
            boto3.setup_default_session(profile_name=sys.argv[1])
        except :
            print ("Oops! there is something wrong with the profile - " + sys.argv[1])
            sys.exit()

    whitelist(getpublicip(), findSecurityGroups())


if __name__ == '__main__':
    main()