#!/usr/bin/env python3

'''
act-connet.py
Author: Krishna V
https://github/com/krishna-v/act-broadband/act-connect.py

Description: Script to interact with the new version portal of ACT Broadband
(circa Nov' 2022) 

act-connect.py -h for usage.
'''

import os
import time
import re
import base64
import json
from configparser import ConfigParser
import argparse
from urllib.parse import unquote
import netifaces as ni
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import jwt
import requests

headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    'Host': 'selfcare.actcorp.in',
    'Origin': 'https://selfcare.actcorp.in',
    'Referer': 'https://selfcare.actcorp.in/home',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'ngsw-bypass': 'true',
    'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"'
}

ACT_BASEURL = "https://selfcare.actcorp.in"
ACT_TOKENFILE = "/tmp/act_token"
CONF_FILE = "/etc/actbroadband/act.conf"

cookies = {}
globalvars = {}
conf = {}

def dprint(lvl, *args, **kwargs):
    ''' print(or not) based on verbosity level '''
    if lvl <= globalvars['verbosity']:
        print(*args, **kwargs)

def load_conf():
    '''
    Load configuration file /etc/actbroadband/act.conf, containing username and password.
    Supports the old sectionless conf format used by act_login.sh, so this method is pretty hacky.
    '''
    parser = ConfigParser()
    with open(CONF_FILE, 'rb') as cfg:
        parser.read_string("[cfg]\n" + cfg.read().decode('utf-8'))
    global conf
    conf = parser._sections['cfg']

def get_conf(key):
    ''' get configuration item '''
    return conf[key.lower()].strip('"')

def get_cipher():
    ''' create a new instance of AES cipher '''
    key = globalvars['key'].encode('utf-8')
    iv = globalvars['iv'].encode('utf-8')
    return AES.new(key, AES.MODE_CBC, iv=iv)

def encrypt(data):
    ''' encrypt a piece of data'''
    cipher = get_cipher()
    cyphertext = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cyphertext).decode('utf-8')

def decrypt(data):
    ''' decrypt a piece of data'''
    cipher = get_cipher()
    cyphertext = base64.b64decode(unquote(data))
    plaintext = unpad(cipher.decrypt(cyphertext), AES.block_size)
    return plaintext.decode('utf-8')

def do_post(url, data, cookies_, headers_):
    ''' do a post request '''
    return requests.post(url, data=data, cookies=cookies_, headers=headers_)

def scrape_homepage():
    ''' extract cookie and the name of the .js file containing the crypto keys from the ACT portal. '''
    url = f"{ACT_BASEURL}/home"
    response = requests.get(url, headers=headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.text
        for cookie in response.cookies:
            cookies[cookie.name]= cookie.value
            dprint(2, f"Cookie: {cookie.name} = {cookie.value}")
        m = re.search(r'<script src="(main-es2015.+?\.js)"', retdata)
        if m:
            dprint(3, f"Found script {m.group(1)}")
            return m.group(1)
    return None

def scrape_script(script):
    ''' extract crypto keys from the javascript file '''
    url = f"{ACT_BASEURL}/{script}"
    response = requests.get(url, headers=headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.text
        m = re.search('this.iv="(.+?)"', retdata)
        if m:
            dprint(3, "IV:", m.group(1))
            globalvars['iv'] = m.group(1)
        m = re.search('this.secretKey="(.+?)"', retdata)
        if m:
            dprint(3, "SecretKey:", m.group(1))
            globalvars['key'] = m.group(1)
        m = re.search(r'authKey:this.service.encrypt\("(.+?)"\)', retdata)
        if m:
            dprint(3, "AuthKey:", m.group(1))
            globalvars['authkey'] = m.group(1)

def load_token():
    ''' load previously saved JWT token from local file '''
    if not os.path.isfile(ACT_TOKENFILE):
        dprint(1, "No tokenfile found")
        return
    with open(ACT_TOKENFILE, 'rb') as tk:
        jwtToken = tk.read()
        output = jwt.decode(jwtToken, globalvars['authkey'],
                    algorithms=["HS256", "HS384", "HS512"],
                    options={ "verify_signature": False })
        dprint(2, "Found Token in file: ", output)
        now = int(time.time())
        if output['exp'] > now + 30:
            dprint(2, "Token still valid")
            globalvars['jwtToken'] = jwtToken.decode('utf-8')
            globalvars['jwt_exp'] = output['exp']
        else:
            dprint(2, "Token expired. Ignoring.")

def initialize():
    ''' do initialization functions '''
    script = scrape_homepage()
    if script:
        scrape_script(script)
    load_token()

def check_valid_user():
    ''' check if user is valid. the ACT portal does this before login, but it doesn't appear necessary '''
    url = f"{ACT_BASEURL}/v1/subscriberdetails/profile/checkValidUser"
    data = { "userId": f"{globalvars['b64user']}" }
    response = do_post(url, json.dumps(data), cookies, headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        retdata['accountNo'] = decrypt(retdata['accountNo'])
        retdata['message'] = decrypt(retdata['message'])
        retdata['errorCode'] = decrypt(retdata['errorCode'])
        retdata['status'] = decrypt(retdata['status'])
        dprint(2, f"Data: {retdata}")
    return response.status_code

def login_by_userid():
    ''' login using the user-id and password provided by ACT. '''
    url = f"{ACT_BASEURL}/v1/subscriberlogin/loginByUserId"
    data = {
        "userId": f"{globalvars['b64user']}",
        "userPwd": f"{globalvars['b64pass']}",
        "networkType": "ACT",
        "subscriberLoc": "",
        "remoteIP": f"{globalvars['ipaddr']}",
        "ecType": ""
    }
    dprint(3, url, data, cookies)
    response = do_post(url, json.dumps(data), cookies, headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        retdata['errorCode'] = decrypt(retdata['errorCode'])
        dprint(2, f"Data: {retdata}")
    return response.status_code

def authenticate():
    ''' get a JWT token. This is required by some of the functions on the portal. '''
    url = f"{ACT_BASEURL}/v1/jwt/authenticate"
    plain_authkey = globalvars['authkey']
    b64authkey = encrypt(plain_authkey.encode('utf-8'))
    plain_source = f"selfcare_{get_conf('USERID')}"
    b64source = encrypt(plain_source.encode('utf-8'))
    data = {
        "source": b64source,
        "authKey": b64authkey
    }
    response = do_post(url, json.dumps(data), cookies, headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        dprint(2, retdata)
        jwtToken = retdata['jwtToken']
        output = jwt.decode(jwtToken, plain_authkey,
                    algorithms=["HS256", "HS384", "HS512"],
                    options={ "verify_signature": False })
        dprint(2, output)
        globalvars['jwtToken'] = jwtToken
        globalvars['jwt_exp'] = output['exp']
        with open(ACT_TOKENFILE, 'wb') as tk:
            tk.write(jwtToken.encode('utf-8'))
    return response.status_code

def get_token():
    '''
    check if we have a valid token and return it,
    else call authenticate to get a fresh one.
    '''
    now = int(time.time())
    if globalvars.get('jwt_exp', 0) < now + 30:
        authenticate()
    return globalvars['jwtToken']

def user_info(silent):
    '''
    get user information. This also gets the user city, which is needed in other functions,
    so we call it silently if we need to use it for that purpose
    '''
    url = f"{ACT_BASEURL}/profile/userInfo"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {get_token()}"
    data = { "accountNo": f"{globalvars['b64user']}" }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        globalvars['city'] = retdata['city']
        globalvars['b64phone'] = retdata['cellulerPhoneNo']
        retdata['userId'] = decrypt(retdata['userId'])
        retdata['accountNo'] = decrypt(retdata['accountNo'])
        retdata['streetAddress'] = decrypt(retdata['streetAddress'])
        retdata['secAddress'] = decrypt(retdata['secAddress'])
        retdata['emailAddress'] = decrypt(retdata['emailAddress'])
        retdata['fullName'] = decrypt(retdata['fullName'])
        retdata['cellulerPhoneNo'] = decrypt(retdata['cellulerPhoneNo'])
        dprint(silent, retdata)
    return response.status_code

def encoded_auth_token():
    ''' the ACT portal does this but we don't seem to use it. Included for completeness '''
    url = f"{ACT_BASEURL}/v1/servicerequest/encodedAuthToken"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {get_token()}"
    data = {
        "accountNo": f"{globalvars['b64user']}",
        "userId": f"{globalvars['b64user']}"
    }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        retdata['authtext'] = decrypt(retdata['authtext'])
        retdata['token'] = decrypt(retdata['token'])
        print(retdata)
    return response.status_code

def location_details(city):
    '''
    get information about ACT infra for a city.
    This is required to get usage and plan info
    '''
    url = f"{ACT_BASEURL}/v1/ippool/locationDetails"
    data = { "location": city }
    response = do_post(url, json.dumps(data), cookies, headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        dprint(1, retdata)
        return retdata
    return None

def usage_details():
    ''' get usage information for this account '''
    if 'city' not in globalvars:
        user_info(1)
    locinfo = location_details(globalvars['city'])
    url = f"{ACT_BASEURL}/v1/user/usage/usageDetails/"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {get_token()}"
    data = {
        "accountNo": f"{globalvars['b64user']}",
        "userId": f"{globalvars['b64user']}",
        "phone": f"{globalvars['b64phone']}",
        "location": locinfo['locationCode'],
        "ecType": locinfo['ecType']
    }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        print(retdata)
    return response.status_code

def agreement_info():
    ''' get the plan details for this account '''
    url = f"{ACT_BASEURL}/v1/user/usage/agreementInfo"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {get_token()}"
    data = {
        "accountNo": f"{globalvars['b64user']}",
        "userId": f"{globalvars['b64user']}",
        "ecType": "",
        "location": "",
        "mobileNo": ""
    }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        print(retdata)
    return response.status_code

def main():
    ''' main. Parse arguments and execute the appropriate functions '''
    parser = argparse.ArgumentParser(description='Interact with ACT Broadband')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                            help='Be verbose. Repeat for even more verbosity (e.g. -vvv')
    parser.add_argument('-c', '--check', action='store_true',
                            help='check if user is valid')
    parser.add_argument('-l', '--login', action='store_true',
                            help='Log in to ACT Broadband account')
    parser.add_argument('-i', '--info', action='store_true',
                            help='Retrieve Account User Information')
    parser.add_argument('-u', '--usage', action='store_true',
                            help='Retrieve Usage Details')
    parser.add_argument('-p', '--plan', action='store_true',
                            help='Retrieve Plan Details')
    args = parser.parse_args()
    globalvars['verbosity'] = args.verbose

    load_conf()
    initialize()

    globalvars['b64user'] = encrypt(get_conf('USERID').encode('utf-8'))
    globalvars['b64pass'] = encrypt(get_conf('PASSWORD').encode('utf-8'))
    wan_ip = ni.ifaddresses(get_conf('ACT_IF'))[ni.AF_INET][0]['addr']
    globalvars['ipaddr'] = wan_ip

    if args.check:
        check_valid_user()

    if args.login:
        login_by_userid()

    if args.info:
        user_info(0)

    if args.usage:
        usage_details()

    if args.plan:
        agreement_info()

if __name__ == "__main__":
    main()
