#!/usr/bin/python
DOCUMENTATION = '''
---
module: aws_check_for_user
short_description: Check if user is in AWS IAM
'''

EXAMPLES = '''
  - name: check for user
    aws_check_for_user:
      aws_key: admin
      aws_secret: 1234567
      iam_user: colab_user

'''
from ansible.module_utils.basic import *
import boto3


def check_for_user(data: dict) -> (bool, bool, bool):
    try:
        client = boto3.client('iam',
                              aws_access_key_id=data['aws_key'],
                              aws_secret_access_key=data['aws_secret'])

        response = client.get_user(
            UserName=data['iam_user']
        )
        if response.get('User'):
            return False, False, True
        else:
            return False, False, False
    except client.exceptions.NoSuchEntityException:
        return False, False, False
    except:
        return True, False, False


def main():
    fields = {
        "aws_key": {"required": True, "type": "str"},
        "aws_secret": {"required": True, "type": "str"},
        "iam_user": {"required": True, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = check_for_user(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, user_present=result)
    else:
        module.fail_json(msg="Error")


if __name__ == '__main__':
    main()
