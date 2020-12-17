#!/usr/bin/python
DOCUMENTATION = '''
---
module: update_dynamo_directory
short_description: Add/remove account records from AWS dynamodb
'''

EXAMPLES = '''
  - name: update or delete user record
    update_dynamo_directory:
      action: "update"
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_directory
      colab_email: user1@domain.com
      colab_username: user1
      colab_password: encrypted_password456

  - name: delete user record
    update_dynamo_directory:
      action: "delete"
      aws_key: admin
      aws_secret: 1234567
      aws_region: us-east-1
      dynamo_table: colab_directory
      colab_email: user1@domain.com
'''
from ansible.module_utils.basic import *
import boto3


def update_record(updated_dict: dict, data: dict) -> int:
    try:
        dynamodb_client = boto3.client('dynamodb',
                                       region_name=data['aws_region'],
                                       aws_access_key_id=data['aws_key'],
                                       aws_secret_access_key=data['aws_secret'])

        response = dynamodb_client.put_item(
            TableName=data['dynamo_table'],
            Item={
                "email": {"S": f"{updated_dict['email']}"},
                "username": {"S": f"{updated_dict['username']}"},
                "password": {"S": f"{updated_dict['password']}"},
                "creation_date": {"S": f"{updated_dict['creation_date']}"},
                "renewal_date": {"S": f"{updated_dict['renewal_date']}"},
                "renewal_request_send_date": {"S": f"{updated_dict['renewal_request_send_date']}"}
            }
        )
    except Exception:
        return 500
    return response['ResponseMetadata']['HTTPStatusCode']  # expect 200


def update_dict(convert_dict: dict, ansible_input: dict) -> dict:
    import time
    epoch_time_now = int(time.time())
    convert_dict['email'] = ansible_input['colab_email']
    convert_dict['username'] = ansible_input['colab_username']
    convert_dict['password'] = ansible_input['colab_password']
    convert_dict['creation_date'] = convert_dict.get('creation_date', epoch_time_now)
    convert_dict['renewal_date'] = convert_dict.get('renewal_date', '')
    convert_dict['renewal_request_send_date'] = convert_dict.get('renewal_request_send_date', '')
    return convert_dict


def convert_download_item_result_to_dict(get_item_result: dict) -> dict:
    if get_item_result.get('Item'):
        return {'email': get_item_result['Item']['email']['S'],
                'username': get_item_result['Item']['username']['S'],
                'password': get_item_result['Item']['password']['S'],
                'creation_date': get_item_result['Item']['creation_date']['S'],
                'renewal_date': get_item_result['Item']['renewal_date']['S'],
                'renewal_request_send_date': get_item_result['Item']['renewal_request_send_date']['S']
                }
    else:
        return {}


def update(data: dict) -> (bool, bool, int):
    here, result = download_item(data)
    result_dict = convert_download_item_result_to_dict(result)
    updated_dict = update_dict(result_dict, data)
    if update_record(updated_dict, data) == 200:
        return False, True, 200
    else:
        return True, False, 500


def download_item(data: dict) -> (bool, dict):
    response = {}
    try:
        dynamodb = boto3.client('dynamodb',
                                region_name=data['aws_region'],
                                aws_access_key_id=data['aws_key'],
                                aws_secret_access_key=data['aws_secret'])
        response = dynamodb.get_item(
            TableName=data['dynamo_table'],
            Key={'email': {'S': data['colab_email']}})
    except:
        response['ResponseMetadata']['HTTPStatusCode'] = 500
        return False, response
    if response.get('Item'):
        return True, response
    return False, response


def delete(data: dict) -> (bool, bool, int):
    # check for record here, result
    here, result = download_item(data)

    if result['ResponseMetadata']['HTTPStatusCode'] != 200:  # Then error occured
        return True, False, result['ResponseMetadata']['HTTPStatusCode']

    if here:
        dynamodb = boto3.resource('dynamodb',
                                  region_name=data['aws_region'],
                                  aws_access_key_id=data['aws_key'],
                                  aws_secret_access_key=data['aws_secret'])
        try:
            table = dynamodb.Table(data['dynamo_table'])

            response = table.delete_item(Key={
                'email': data['colab_email']
            })
        except:
            return True, False, 500
    return False, True, 200


def main():
    fields = {
        "action": {"required": True, "choices": ["update", "delete"], "type": "str"},
        "aws_key": {"required": True, "type": "str"},
        "aws_secret": {"required": True, "type": "str"},
        "aws_region": {"required": True, "type": "str"},
        "dynamo_table": {"required": True, "type": "str"},
        "colab_email": {"required": True, "type": "str"},
        "colab_username": {"required": True, "type": "str"},
        "colab_password": {"required": True, "type": "str"}
    }

    choice_map = {
        "update": update,
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
