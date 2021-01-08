#!/usr/bin/python
DOCUMENTATION = '''
---
module: dynamo_get_record
short_description: Get a record from AWS dynamodb
'''

EXAMPLES = '''
  - name: retrieve a dynamodb record
    dynamo_get_record:
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_directory
      colab_email: user1@domain.com

'''
from ansible.module_utils.basic import *
import boto3


def download_item(data: dict) -> (bool, bool, dict):
    try:
        dynamodb_client = boto3.client('dynamodb',
                                       region_name=data['aws_region'],
                                       aws_access_key_id=data['aws_key'],
                                       aws_secret_access_key=data['aws_secret'])
        response = dynamodb_client.get_item(
            TableName=data['dynamo_table'],
            Key={'email': {'S': data['colab_email']}})
        if response.get('Item'):
            return False, False, response.get('Item')
        else:
            return True, False, dict()
    except Exception:
        return True, False, dict()


def main():
    fields = {
        "aws_key": {"required": True, "type": "str"},
        "aws_secret": {"required": True, "type": "str"},
        "aws_region": {"required": True, "type": "str"},
        "dynamo_table": {"required": True, "type": "str"},
        "colab_email": {"required": True, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = download_item(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error")


if __name__ == '__main__':
    main()
