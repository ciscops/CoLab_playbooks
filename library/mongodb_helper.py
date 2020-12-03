#!/usr/bin/python
DOCUMENTATION = '''
---
module: mongodb_helper
short_description: Add/remove records from mongodb
'''

EXAMPLES = '''
  - name: add or update user record
    mongodb_helper:
      action: "add"
      mongo_username: admin
      mongo_password: password123
      mongo_server: 10.0.0.1
      mongo_port: 27017
      mongo_database_name: db1
      mongo_collection_name: col1
      colab_username: user1
      colab_password: password456

  - name: remove user record
    mongodb_helper:
      action: "remove"
      mongo_username: admin
      mongo_password: password123
      mongo_server: 10.0.0.1
      mongo_port: 27017
      mongo_database_name: db1
      mongo_collection_name: col1
      colab_username: user1
'''
from ansible.module_utils.basic import *
from pymongo import MongoClient
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def db_creds(user, password, ip, port):
    mongo_url = 'mongodb://' + user + ':' + password + '@' + ip + ':' + port
    return MongoClient(mongo_url)


def add_record(mycol, username, password):
    error = False
    query_lab_filter = {"name": username}
    try:
        result = mycol.find_one(query_lab_filter)
        if result is None:
            mycol.insert_one({"name": username,
                              "password": password})
        else:
            doc = mycol.find_one_and_update(
                {'_id': result['_id']},
                {'$set': {'password': password}
                 }
            )
    except:
        error = True
    return error


def remove_record(mycol, username):
    error = False
    try:
        query_lab_filter = {"name": username}
        result = mycol.find_one(query_lab_filter)
        if result:
            mycol.delete_one(query_lab_filter)
    except:
        error = True
    return error


def process(**kwargs):
    db_client = db_creds(kwargs["mongo_username"],
                         kwargs["mongo_password"],
                         kwargs["mongo_server"],
                         kwargs["mongo_port"])
    db = db_client[kwargs["mongo_database_name"]]
    collection = db[kwargs["mongo_collection_name"]]

    if kwargs["action"] == 'add':
        error = add_record(collection,
                   kwargs["colab_username"],
                   kwargs["colab_password"])
    else:
        error = remove_record(collection,
                      kwargs["colab_username"])

    db_client.close()
    return error


def main():
    fields = {
        "action": {"required": True, "choices": ["add", "remove"], "type": "str"},
        "mongo_username": {"required": True, "type": "str"},
        "mongo_password": {"required": True, "type": "str"},
        "mongo_server": {"required": True, "type": "str"},
        "mongo_port": {"required": True, "type": "str"},
        "mongo_database_name": {"required": True, "type": "str"},
        "mongo_collection_name": {"required": True, "type": "str"},
        "colab_username": {"required": True, "type": "str"},
        "colab_password": {"required": True, "type": "str"},
    }

    module = AnsibleModule(argument_spec=fields)
    is_error = process(module.params)

    if not is_error:
        module.exit_json(changed=True)
    else:
        module.fail_json(msg="Error")


if __name__ == '__main__':
    main()
