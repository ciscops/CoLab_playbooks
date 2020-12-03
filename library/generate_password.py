#!/usr/bin/python
DOCUMENTATION = '''
---
module: generate_password
short_description: Generates a 20 character password
'''

EXAMPLES = '''
  - name: Generate Password
    generate_password:
'''
from ansible.module_utils.basic import *
import string
import secrets
import random


def main():
    password = "".join(secrets.choice(string.ascii_uppercase) for x in range(7))
    password += "".join(secrets.choice(string.ascii_lowercase) for x in range(7))
    password += "".join(secrets.choice(string.digits) for x in range(3))
    password += "".join(secrets.choice("_[}^") for x in range(3))
    module = AnsibleModule()
    module.exit_json(changed=True, meta=''.join(random.sample(password, len(password))))


if __name__ == '__main__':
    main()
