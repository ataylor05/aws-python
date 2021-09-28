import boto3

client = boto3.client('iam')

def create_role():
    response = client.create_role(
        Path='string',
        RoleName='string',
        AssumeRolePolicyDocument='string',
        Description='string',
        MaxSessionDuration=123,
        PermissionsBoundary='string',
        Tags=[
            {
                'Key': 'string',
                'Value': 'string'
            },
        ]
    )

def create_group(group_name, path="/"):
    try:
        response = client.create_group(
            Path=path,
            GroupName=group_name
        )
        return response["Group"]
    except Exception as error: print(error)

def get_group(group_name):
    try:
        response = client.get_group(
            GroupName=group_name
        )
        return response["Group"]
    except Exception as error: print(error)

def create_user(user_name, permissions_boundary=None, tags=[], path="/"):
    try:
        if permissions_boundary == None:
            response = client.create_user(
                Path=path,
                UserName=user_name,
                Tags=tags
            )
        else:
            response = client.create_user(
                Path=path,
                UserName=user_name,
                PermissionsBoundary=permissions_boundary,
                Tags=tags
            )
        return response["User"]
    except Exception as error: print(error)

def add_user_to_group(user_name, group_name):
    try:
        response = client.add_user_to_group(
            GroupName=group_name,
            UserName=user_name
        )
        return response["ResponseMetadata"]
    except Exception as error: print(error)

def attach_policy_to_group(group_name, policy_arn):
    try:
        client.attach_group_policy(
            GroupName=group_name,
            PolicyArn=policy_arn
        )
        return "Policy has been attached to group"
    except Exception as error: print(error)


