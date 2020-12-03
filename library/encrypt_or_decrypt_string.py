#!/usr/bin/python
DOCUMENTATION = '''
---
module: encrypt_or_decrypt_string
short_description: Encrypts or decrypts a string using a key
'''

EXAMPLES = '''
  - name: Encrypt string
    encrypt_or_decrypt_string:
      action: "encrypt"
      message: "this message needs to be confidential"
      key: "somelongkey"

  - name: Decrypt string
    encrypt_or_decrypt_string:
      action: "decrypt"
      message: "sfsfasomeencyrptedmessagesfsdf"
      key: "somelongkey"
'''
from ansible.module_utils.basic import *
from cryptography.fernet import Fernet


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message).decode()


def decrypt(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token).decode()


def main():
    fields = {
        "action": {"required": True, "choices": ["encrypt", "decrypt"], "type": "str"},
        "message": {"required": True, "type": "str"},
        "key": {"required": True, "type": "str"}
    }
    choice_map = {
        "encrypt": encrypt,
        "decrypt": decrypt,
    }
    module = AnsibleModule(argument_spec=fields)
    result = choice_map.get(module.params['action'])(module.params['message'].encode(),
                                                     module.params['key'].encode())
    module.exit_json(changed=True, meta=result)


if __name__ == '__main__':
    main()
