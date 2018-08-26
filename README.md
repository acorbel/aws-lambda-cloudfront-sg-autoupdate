# aws-lambda-cloudfront-sg-autoupdate
AutoUpdate security groups based on Cloudfront IPs

__It supports multi securiy group updates to bypass the 50 rules restrictions on SGs.__

## HowTo
1. Create at least 2 security groups (if you are under the 50 rules per SG restriction)
2. Add the following tags to each SG: 
    * AutoUpdate: true
    * Name: cloudfront
    * Port: PORT (where PORT is the port you want to allow from Cloudfront)
3. Create the lambda with the content of index.js (nodejs 8.10)
4. Configure the lambda constants (PORT and RULE_PER_SG)
5. Subscribe to the SNS event: arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged



From https://github.com/awslabs/aws-cloudfront-samples/tree/master/update_security_groups_lambda
