# app.py - intentionally vulnerable patterns for scanner testing
import os
import sqlite3
import pickle
import yaml
import json
import random
import hmac
import secrets
import requests
from urllib.request import urlopen

DEBUG = True

def login(username, password):
    # SQL Injection
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)


def cmd_exec(host):
    # Command Injection
    os.system("ping -c 1 " + host)


def ssrf(url):
    # SSRF
    requests.get(url)


def xxe(xml_data):
    # XML injection/XXE
    import xml.etree.ElementTree as ET
    ET.parse(xml_data)


def insecure_deser(blob):
    # Insecure Deserialization
    pickle.loads(blob)


def weak_crypto(data):
    # Weak crypto
    import hashlib
    hashlib.md5(data.encode()).hexdigest()


def hardcoded_secrets():
    api_key = "abc123"
    password = "password123"
    secret_key = "supersecret"
    return api_key, password, secret_key


def jwt_weak():
    import jwt
    jwt.encode({"user": "a"}, "short", algorithm="HS256")


def jwt_none(token):
    import jwt
    jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])


def timing_attack(password, user_input):
    if password == user_input:
        return True
    return False


def debug_exposure():
    print("debug=", DEBUG)


def log_injection(user_input):
    import logging
    logging.getLogger().info("User: " + user_input)


def path_traversal(path):
    open(path, "r").read()


def file_upload(file_obj):
    # Unrestricted file upload
    with open("/tmp/" + file_obj.filename, "wb") as f:
        f.write(file_obj.read())


def zip_slip(archive_path):
    import zipfile
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall("/tmp/extract")


def insecure_random_token():
    return str(random.random())


def cleartext_transmission():
    url = "http://example.com/password?token=abc"
    return urlopen(url)


def disabled_tls():
    requests.get("https://example.com", verify=False)


def insecure_cookie(resp):
    resp.set_cookie("session", "abc")


def cors_misconfig(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"


def template_injection(user_input):
    from jinja2 import Template
    Template(user_input).render()


def nosql_injection(user_input, collection):
    collection.find({"$where": user_input})


def graphql_injection(query):
    execute_graphql(query)


def sensitive_data_exposure(user):
    return json.dumps({"password": user.password, "token": user.token})


def race_condition(path):
    if os.path.exists(path):
        open(path, "w").write("data")

