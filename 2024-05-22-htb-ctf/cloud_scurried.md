# [Cloud - easy] Scurried

We are only given 1 element: `AROAXYAFLIG2BLQFIIP34`. This string is an [AWS Unique Identifier](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes) for a role. The flag is the AWS Role ARN within the `HTB{}` flag format.

Following the advice of [this website](https://hackingthe.cloud/aws/enumeration/enumerate_principal_arn_from_unique_id/), we can easily derive a role ARN from its Unique Identifier by creating a policy that refers to it.

Using a test AWS account, we create a test role with the following trust policy:

```
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "AROAXYAFLIG2BLQFIIP34"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

Saving the role containing the trust policy and going back to it, it now displays:

```
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::532587168180:role/vault101"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

The flag is `HTB{arn:aws:iam::532587168180:role/vault101}`