#!/usr/bin/python
DOCUMENTATION = '''
---
module: dynamo_gitlab
short_description: Add/remove gitlab deployment records from AWS dynamodb
'''

EXAMPLES = '''
  - name: create gitlab record
    dynamo_gitlab:
      action: "create"
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_gitlab
      colab_username: user1

  - name: delete gitlab record
    dynamo_gitlab:
      action: "delete"
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_gitlab
      colab_username: user1
'''
from ansible.module_utils.basic import *
import boto3


def create(data: dict) -> (bool, bool, int):
    try:
        dynamodb_client = boto3.client('dynamodb',
                                       region_name=data['aws_region'],
                                       aws_access_key_id=data['aws_key'],
                                       aws_secret_access_key=data['aws_secret'])

        response = dynamodb_client.put_item(
            TableName=data['dynamo_table'],
            Item={
                "username": {"S": f"{data['colab_username']}"},
                "age_renewed": {"S": "0"},
                "age_renewal_request_sent": {"S": "0"},
                "renewal_request_sent_count": {"S": "0"}
            }
        )
        return False, True, 200
    except Exception:
        return True, False, 500


def delete(data: dict) -> (bool, bool, int):

    dynamodb = boto3.resource('dynamodb',
                              region_name=data['aws_region'],
                              aws_access_key_id=data['aws_key'],
                              aws_secret_access_key=data['aws_secret'])
    try:
        table = dynamodb.Table(data['dynamo_table'])

        response = table.delete_item(Key={
            'username': data['colab_username']
        })
        return False, True, 200
    except:
        return True, False, 500


def main():
    fields = {
        "action": {"required": True, "choices": ["create", "delete"], "type": "str"},
        "aws_key": {"required": True, "type": "str"},
        "aws_secret": {"required": True, "type": "str"},
        "aws_region": {"required": True, "type": "str"},
        "dynamo_table": {"required": True, "type": "str"},
        "colab_username": {"required": False, "type": "str"}
    }

    choice_map = {
        "create": create,
        "delete": delete,
    }
    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['action'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error")


if __name__ == '__main__':
    main()
