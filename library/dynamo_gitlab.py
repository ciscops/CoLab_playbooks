#!/usr/bin/python
DOCUMENTATION = '''
---
module: dynamo_gitlab
short_description: Add/Update/Remove/Check for gitlab deployment records AWS dynamodb
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
  
  - name: check gitlab record
    dynamo_gitlab:
      action: "check_record"
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_gitlab
      colab_username: user1
'''
from ansible.module_utils.basic import *
import boto3
import datetime


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
                "date_renewed": {"S": datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')},
                "date_renewal_request_sent": {"S": "0"},
                "renewal_request_sent_count": {"S": "0"}
            }
        )
        return False, True, 200
    except Exception:
        return True, False, 500


def delete(data: dict) -> (bool, bool, int):
    try:
        dynamodb = boto3.resource('dynamodb',
                                  region_name=data['aws_region'],
                                  aws_access_key_id=data['aws_key'],
                                  aws_secret_access_key=data['aws_secret'])

        table = dynamodb.Table(data['dynamo_table'])

        response = table.delete_item(Key={
            'username': data['colab_username']
        })
        return False, True, 200
    except:
        return True, False, 500


def check_record(data: dict) -> (bool, bool, bool):
    try:
        dynamodb = boto3.client('dynamodb',
                                region_name=data['aws_region'],
                                aws_access_key_id=data['aws_key'],
                                aws_secret_access_key=data['aws_secret'])
        response = dynamodb.get_item(TableName=data['dynamo_table'],
                                     Key={'username': {'S': data['colab_username']}})
        if response.get('Item'):
            return False, False, True
        else:
            return False, False, False
    except:
        return True, False, False


def main():
    fields = {
        "action": {"required": True, "choices": ["create", "delete", "check_record"], "type": "str"},
        "aws_key": {"required": True, "type": "str"},
        "aws_secret": {"required": True, "type": "str"},
        "aws_region": {"required": True, "type": "str"},
        "dynamo_table": {"required": True, "type": "str"},
        "colab_username": {"required": False, "type": "str"}
    }

    choice_map = {
        "create": create,
        "delete": delete,
        "check_record": check_record,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['action'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error")


if __name__ == '__main__':
    main()
