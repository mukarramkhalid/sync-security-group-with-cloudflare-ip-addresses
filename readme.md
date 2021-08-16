### What is it?
This Lambda function allows us to keep an AWS Security Group up-to-date with Cloudflare IP addresses for the given ports.

### Why?
There are other scripts and Lambda functions available online but there are quite a few problems with them. The first few search results point to [johnmccuk/cloudflare-ip-security-group-update](https://github.com/johnmccuk/cloudflare-ip-security-group-update). I don't want to use it because:

- It uses Python 2.7, which is deprecated.
- It does not remove old rules and IP addresses which do not exist anymore as described in [this issue](https://github.com/johnmccuk/cloudflare-ip-security-group-update/issues/3).
- Has some other [issues](https://github.com/johnmccuk/cloudflare-ip-security-group-update/issues/2).

Another script [sys0dm1n/lambda-cloudflare-ip-security-group-update](https://github.com/sys0dm1n/lambda-cloudflare-ip-security-group-update) has the similar problems.

My use case is very simple. I needed a Lambda function that would sync an AWS Security Group with Cloudflare IP addresses and keep it up-to-date.

### Is there something I should know?
- This Lambda function does not use environment variables. It uses hard-coded values which are not sensitive details at all.
- However, it should be quite easy to integrate environment variables. I don't feel like implementing it at this point, but I'll accept PRs which would make use of environment variables, if defined.
- This script works with only one security group at a time.
- You need one dedicated security group for Cloudflare. Any extra ingress rules will be removed from the security group. As the name suggests, this Lambda function syncs up the security group with Cloudflare IP addresses for the given ports. Syncing also means removing things that do not exist.

### How to use it?
1. Create a Lambda function with Python 3.8 runtime environment. 
2. On [line # 6](https://github.com/mukarramkhalid/sync-security-group-with-cloudflare-ip-addresses/blob/cfa440818287593006e60ef714222a7c564719b6/sync-security-group-with-cloudflare-ip-addresses.py#L6), replace `security_group_id` with the ID of your AWS Security Group.
3. On [line # 7](https://github.com/mukarramkhalid/sync-security-group-with-cloudflare-ip-addresses/blob/cfa440818287593006e60ef714222a7c564719b6/sync-security-group-with-cloudflare-ip-addresses.py#L7-L10), specify port ranges for which you want to create the rules. For example, I want to use this security group to restrict ports `80` and `443`. 
```json
[
    {"from": 80, "to": 80},
    {"from": 443, "to": 443},
]
```
4. It should work fine with `128 MBs` of memory and `1 minute` timeout. You can use the lower values but I haven't tried with lower memory and timeout.
5. You can use `EventBridge (CloudWatch Events)` to trigger this Lambda function once every hour with schedule expression `cron(0 * * * ? *)`. 
6. This Lambda function requires an execution role with the following policy.
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```
