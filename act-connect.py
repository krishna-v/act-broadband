#!/usr/bin/python3

import requests
import json
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import netifaces as ni
from configparser import ConfigParser
import jwt
import re
import time
import os
import argparse

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
    'sec-ch-ua-platform': '"Windows"Accept: application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'sec-ch-ua-platform': '"Windows"'
}

act_baseurl = "https://selfcare.actcorp.in"
act_tokenfile = "/tmp/act_token"
conf_file = "/etc/actbroadband/act.conf"

cookies = {}
globalvars = {}
conf = {}

def dprint(lvl, *args, **kwargs):
    if lvl <= globalvars['verbosity']:
        print(*args, **kwargs)

def loadConf():
    parser = ConfigParser()
    with open(conf_file, 'rb') as cfg:
        parser.read_string("[cfg]\n" + cfg.read().decode('utf-8'))
    global conf
    conf = parser._sections['cfg']

def getConf(key):
    return conf[key.lower()].strip('"')
    

def getCipher():
    key = globalvars['key'].encode('utf-8')
    iv = globalvars['iv'].encode('utf-8')
    return AES.new(key, AES.MODE_CBC, iv=iv)

def encrypt(data):
    cipher = getCipher()
    cyphertext = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cyphertext).decode('utf-8')

def decrypt(data):
    cipher = getCipher()
    cyphertext = base64.b64decode(data)
    plaintext = unpad(cipher.decrypt(cyphertext), AES.block_size)
    return plaintext.decode('utf-8')

def do_post(url, data, cookies, headers):
    return requests.post(url, data=data, cookies=cookies, headers=headers)

def scrapeHomePage():
    url = f"{act_baseurl}/home"
    response = requests.get(url, headers=headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.text
        for cookie in response.cookies:
            cookies[cookie.name]= cookie.value
            dprint(2, f"Cookie: {cookie.name} = {cookie.value}")
        m = re.search('<script src="(main-es2015.+?\.js)"', retdata)
        if m:
            dprint(3, f"Found script {m.group(1)}")
            return m.group(1)

def scrapeScript(script):
    url = f"{act_baseurl}/{script}"
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
        m = re.search('authKey:this.service.encrypt\("(.+?)"\)', retdata)
        if m:
            dprint(3, "AuthKey:", m.group(1))
            globalvars['authkey'] = m.group(1)

def loadToken():
    if not os.path.isfile(act_tokenfile):
        dprint(1, "No tokenfile found")
        return
    with open(act_tokenfile, 'rb') as tk:
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
    script = scrapeHomePage()
    if script:
        scrapeScript(script)
    loadToken()

def checkValidUser():
    url = f"{act_baseurl}/v1/subscriberdetails/profile/checkValidUser"
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

def loginByUserId():
    url = f"{act_baseurl}/v1/subscriberlogin/loginByUserId"
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
    url = f"{act_baseurl}/v1/jwt/authenticate"
    plain_authkey = globalvars['authkey']
    b64authkey = encrypt(plain_authkey.encode('utf-8'))
    plain_source = f"selfcare_{getConf('USERID')}"
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
        with open(act_tokenfile, 'wb') as tk:
            tk.write(jwtToken.encode('utf-8'))
    return response.status_code

def getToken():
    now = int(time.time())
    if globalvars.get('jwt_exp', 0) < now + 30:
        authenticate()
    return globalvars['jwtToken']

def userInfo(silent):
    url = f"{act_baseurl}/profile/userInfo"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {getToken()}"
    data = { "accountNo": f"{globalvars['b64user']}" }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        globalvars['city'] = retdata['city']
        globalvars['b64phone'] = retdata['cellulerPhoneNo']
        #retdata['streetAddress'] = decrypt(retdata['streetAddress'])
        #retdata['secAddress'] = decrypt(retdata['secAddress'])
        retdata['emailAddress'] = decrypt(retdata['emailAddress'])
        retdata['fullName'] = decrypt(retdata['fullName'])
        retdata['cellulerPhoneNo'] = decrypt(retdata['cellulerPhoneNo'])
        dprint(silent, retdata)
    return response.status_code
    
def encodedAuthToken():
    url = f"{act_baseurl}/v1/servicerequest/encodedAuthToken"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {getToken()}"
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

def locationDetails(city):
    url = f"{act_baseurl}/v1/ippool/locationDetails"
    if not 'city' in globalvars:
        userInfo(1)
    data = { "location": f"{globalvars['city']}" }
    response = do_post(url, json.dumps(data), cookies, headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        dprint(1, retdata)
        return retdata
    return None

def usageDetails():
    if not 'city' in globalvars:
        userInfo(1)
    locInfo = locationDetails(globalvars['city'])
    url = f"{act_baseurl}/v1/user/usage/usageDetails/"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {getToken()}"
    data = {
        "accountNo": f"{globalvars['b64user']}",
        "userId": f"{globalvars['b64user']}",
        "phone": f"{globalvars['b64phone']}",
        "location": locInfo['locationCode'],
        "ecType": locInfo['ecType']
    }
    response = do_post(url, json.dumps(data), cookies, req_headers)
    dprint(1, f"{url}: Status {response.status_code}")
    if response.status_code == 200:
        retdata = response.json()
        print(retdata)
    return response.status_code

def agreementInfo():
    url = f"{act_baseurl}/v1/user/usage/agreementInfo"
    req_headers = headers.copy()
    req_headers['Authorization'] = f"Bearer {getToken()}"
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
    parser = argparse.ArgumentParser(description='Interact with ACT Broadband')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Be verbose. Repeat for even more verbosity (e.g. -vvv')
    parser.add_argument('-c', '--check', action='store_true', help='check if user is valid')
    parser.add_argument('-l', '--login', action='store_true', help='Log in to ACT Broadband account')
    parser.add_argument('-i', '--info', action='store_true', help='Retrieve Account User Information')
    parser.add_argument('-u', '--usage', action='store_true', help='Retrieve Usage Details')
    parser.add_argument('-p', '--plan', action='store_true', help='Retrieve Plan Details')
    args = parser.parse_args()
    globalvars['verbosity'] = args.verbose

    loadConf()
    initialize()

    globalvars['b64user'] = encrypt(getConf('USERID').encode('utf-8'))
    globalvars['b64pass'] = encrypt(getConf('PASSWORD').encode('utf-8'))
    wan_ip = ni.ifaddresses(getConf('ACT_IF'))[ni.AF_INET][0]['addr']
    globalvars['ipaddr'] = wan_ip

    if args.check:
        checkValidUser()

    if args.login:
        loginByUserId()

    if args.info:
        userInfo(0)

    if args.usage:
        usageDetails()

    if args.plan:
        agreementInfo()
    

if __name__ == "__main__":
    main()


