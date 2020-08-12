#!/usr/bin/python
DOCUMENTATION = '''
---
module: vcenter_user_admin
short_description: Add user and/or reset password or delete user from vCenter 6.7
'''

EXAMPLES = '''
  - name: Add user and/or reset passord in vCenter 6.7
    vcenter_user_admin:
      action: "create_or_reset"
      user: "user1"
      user_password_init: "hardpasswordtoguess"
      user_first_name: "first"
      user_last_name: "last"
      user_password_final: "finalhardpasswordtoguess"
      user_group: "operators"
      admin_username: "administrator"
      admin_password: "adminpassword"
      vcenter_address: "vcenter.domain.com"

- name: Delete user vCenter 6.7
    vcenter_user_admin:
      action: "delete"
      user: "user1"
      admin_username: "administrator"
      admin_password: "adminpassword"
      vcenter_address: "vcenter.domain.com"
'''
from ansible.module_utils.basic import *
import paramiko
import time


def prompt_vcsa(chan):
    buff = ''
    while not buff.endswith('> '):
        resp = chan.recv(99999)
        resp1 = resp.decode('utf-8')
        buff += resp1
    return buff


def prompt_shell(chan):
    buff = ''
    while not buff.endswith('$ \x1b[0m'):
        resp = chan.recv(99999)
        resp1 = resp.decode('utf-8')
        buff += resp1
    return buff


def create_or_reset(data):
    commands_vca = ("shell.set --enabled true",)
    commands_shell = ("shell",
        "/usr/lib/vmware-vmafd/bin/dir-cli user create --account {user} --first-name {user_first_name} --last-name {user_last_name} --user-password '{user_password_init}' --login {admin_username} --password '{admin_password}'".format(user=data['user'],user_first_name=data['user_first_name'],user_last_name=data['user_last_name'],user_password_init=data['user_password_init'],admin_username=data['admin_username'],admin_password=data['admin_password']),
        "/usr/lib/vmware-vmafd/bin/dir-cli group modify --name {user_group} --add {user} --login {admin_username} --password '{admin_password}'".format(user_group=data['user_group'],user=data['user'],admin_username=data['admin_username'],admin_password=data['admin_password']),
        "/usr/lib/vmware-vmafd/bin/dir-cli password reset --account {user} --new '{user_password_final}' --login {admin_username} --password '{admin_password}'".format(user=data['user'],user_password_final=data['user_password_final'],admin_username=data['admin_username'],admin_password=data['admin_password']))
    return send_ssh(data, commands_vca, commands_shell)


def delete(data):
    commands_vca = ("shell.set --enabled true",)
    commands_shell = ("shell","/usr/lib/vmware-vmafd/bin/dir-cli user delete --account {user} --login {admin_username} --password '{admin_password}'".format(user=data['user'],admin_username=data['admin_username'],admin_password=data['admin_password']))
    return send_ssh(data, commands_vca, commands_shell)


def send_ssh(data, commands_vca, commands_shell):
    error = False
    changed = False
    status = dict()
    output = ''
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(data['vcenter_address'], username=data['admin_username'], password=data['admin_password'],
                  timeout=5.0)
        time.sleep(0.5)
        ssh = c.invoke_shell()
        time.sleep(0.5)

        for command in commands_vca:
            ssh.send(command + "\n")
            output = prompt_vcsa(ssh)
            print(output)
        for command in commands_shell:
            ssh.send(command + "\n")
            output = prompt_shell(ssh)
            print(output)

        if 'Password was reset successfully' in output:
            status['msg'] = 'Success'
            changed = True
        elif 'ERROR' in output:
            ind = output.index('ERROR')
            msg = output[ind:]
            status['msg'] = msg
        else:
            status['msg'] = 'Failed'
        ssh.close()
    except Exception as e:
        print(e)
        error = True
        status['msg'] = 'Error'
    return error, changed, status


def main():
    fields = {
        "user": {"required": True, "type": "str"},
        "user_password_init": {"required": False, "type": "str"},
        "user_first_name": {"default": "unk", "type": "str"},
        "user_last_name": {"default": "unk", "type": "str"},
        "user_password_final": {"required": False, "type": "str"},
        "user_group": {"required": False, "type": "str"},
        "admin_username": {"required": True, "type": "str"},
        "admin_password": {"required": True, "type": "str"},
        "vcenter_address": {"required": True, "type": "str"},
        "action": {"required": True, "type": "str"}
    }
    choice_map = {
        "create_or_reset": create_or_reset,
        "delete": delete,
    }
    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['action'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error", meta=result)


if __name__ == '__main__':
    main()
