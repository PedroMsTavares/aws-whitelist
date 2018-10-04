# aws-whitelist

This tool is intended to whitelist your public ip in a desired security group.

### Usage : 

python3 whitelist.py --aws_profile [aws profile name] --aws_region [aws region]

python3 whitelist.py --aws_profile [aws profile name] --aws_region [aws region] --remove

### Example : 

python3 whitelist.py --aws_profile dev --aws_region eu-west-1

python3 whitelist.py --aws_profile dev --aws_region eu-west-1 --remove

### Help :

python3 whitelistpy -h