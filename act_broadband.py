#!/usr/bin/env python3

'''
act_broadband.py
Author: Krishna V
https://github/com/krishna-v/act-broadband/act_broadband.py

Description: Module to interact with the new ACT Broadband portal
(circa Nov 2022 onwards)
act-connect.py -h for usage.
'''

import os
import time
import re
import base64
import json
from configparser import ConfigParser
import argparse
import urllib.parse as urlparse
import netifaces as ni
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad
import jwt
import requests

class ACTConnection:
    '''
    Class that encapsulates all ACT broadband connection functionality.
    The _main() method in this file shows how to use it,
    and allows execution of all key functions from the command-line.
    '''
    ACT_BASEURL = "https://selfcare.actcorp.in"
    ACT_TOKENFILE = "/tmp/act_token"
    CONF_FILE = "/etc/actbroadband/act.conf"
    FALLBACK_KEY = "IJ&Kl$!QV#?NwG@D"
    FALLBACK_IV = "QV4wX2nxCsNxCJHD"
    FALLBACK_AUTHKEY = "selfcare@1234"

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
        'User-Agent':  ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/107.0.0.0 Safari/537.36'),
        'ngsw-bypass': 'true',
        'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    }

    cookies = {}
    conf = {}
    rt_vars = {}
    verbosity = 0

    def __init__(self, verbosity=0):
        self.verbosity = verbosity

    def set_verbosity(self, verbosity):
        ''' 'nuff said '''
        self.verbosity = verbosity

    def _dprint(self, lvl, *args, **kwargs):
        ''' print(or not) based on verbosity level '''
        if lvl <= self.verbosity:
            print(f"{time.ctime()}", *args, **kwargs, flush=True)

    def _load_conf(self):
        '''
        Load configuration file /etc/actbroadband/act.conf, containing username and password.
        Supports the sectionless conf format used by act_login.sh, so this method is pretty hacky.
        '''
        parser = ConfigParser()
        with open(self.CONF_FILE, 'rb') as cfg:
            parser.read_string("[cfg]\n" + cfg.read().decode('utf-8'))
        self.conf = parser._sections['cfg']

    def get_conf(self, key):
        ''' get configuration item '''
        return self.conf[key.lower()].strip('"')

    def get_cipher(self):
        ''' create a new instance of AES cipher '''
        key = self.rt_vars['key'].encode('utf-8')
        init_vector = self.rt_vars['iv'].encode('utf-8')
        return AES.new(key, AES.MODE_CBC, iv=init_vector)

    def _encrypt(self, data):
        ''' encrypt a piece of data'''
        cipher = self.get_cipher()
        cyphertext = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(cyphertext).decode('utf-8')

    def _decrypt(self, data):
        ''' decrypt a piece of data'''
        cipher = self.get_cipher()
        cyphertext = base64.b64decode(urlparse.unquote(data))
        plaintext = unpad(cipher.decrypt(cyphertext), AES.block_size)
        return plaintext.decode('utf-8')

    def _load_cookies(self, cookies):
        '''
            Load cookies from a dict.
            Don't do a dict copy as we may have other cookies set.
        '''
        for cookie in cookies:
            self.cookies[cookie.name]= cookie.value
            self._dprint(2, f"Cookie: {cookie.name} = {cookie.value}")

    def _scrape_homepage(self):
        '''
        extract info from the ACT portal home page.
        This includes a cookie and the name of the .js file containing  crypto keys.
        '''
        url = f"{self.ACT_BASEURL}/home"
        response = requests.get(url, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.text
            self._load_cookies(response.cookies)
            if 'ClientIP' in response.headers:
                self.cookies['remote'] = response.headers['ClientIP']
            p_match = re.search(r'<script src="(main-es2015.+?\.js)"', retdata)
            if p_match:
                self._dprint(3, f"Found script {p_match.group(1)}")
                return p_match.group(1)
        return None

    def _scrape_script(self, script):
        ''' extract crypto keys from the javascript file '''
        url = f"{self.ACT_BASEURL}/{script}"
        response = requests.get(url, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            self._load_cookies(response.cookies)
            retdata = response.text
            # p_match = re.search('this.iv="(.+?)"', retdata)
            p_match = re.search('this.firstAuto="(.+?)"', retdata)
            if p_match:
                iv = p_match.group(1)[:-1]
                self._dprint(3, "IV:", iv)
                self.rt_vars['iv'] = iv
            else:
                self._dprint(1, f"{url}: Could not find IV. Using fallback value!")
                self.rt_vars['iv'] = self.FALLBACK_IV

            # p_match = re.search('this.secretKey="(.+?)"', retdata)
            p_match = re.search('this.lastAuto="(.+?)"', retdata)
            if p_match:
                key = p_match.group(1)[:-2]
                self._dprint(3, "SecretKey:", key)
                self.rt_vars['key'] = key
            else:
                self._dprint(1, f"{url}: Could not find Encryption Key. Using fallback value!")
                self.rt_vars['key'] = self.FALLBACK_KEY

            p_match = re.search(r'authKey:this.service.encrypt\("(.+?)"\)', retdata)
            if p_match:
                self._dprint(3, "AuthKey:", p_match.group(1))
                self.rt_vars['authkey'] = p_match.group(1)
            else:
                self._dprint(1, f"{url}: Could not find Auth Key. Using fallback value!")
                self.rt_vars['authkey'] = self.FALLBACK_AUTHKEY

    def _load_token(self):
        ''' load previously saved JWT token from local file '''
        if not os.path.isfile(self.ACT_TOKENFILE):
            self._dprint(1, "No tokenfile found")
            return
        with open(self.ACT_TOKENFILE, 'rb') as tokenfile:
            jwt_token = tokenfile.read()
            output = jwt.decode(jwt_token, self.rt_vars['authkey'],
                        algorithms=["HS256", "HS384", "HS512"],
                        options={ "verify_signature": False })
            self._dprint(2, "Found Token in file: ", output)
            now = int(time.time())
            if output['exp'] > now + 30:
                self._dprint(2, "Token still valid")
                self.rt_vars['jwtToken'] = jwt_token.decode('utf-8')
                self.rt_vars['jwt_exp'] = output['exp']
            else:
                self._dprint(2, "Token expired. Ignoring.")

    def _get_message_json(self):
        '''
            Get the messageNew.json from the site.
            This seems to be required.
        '''
        url = f"{self.ACT_BASEURL}/assets/messageNew.json"
        response = requests.get(url, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        # TODO: Do something if the response code isn't 200.

    def initialize(self):
        ''' do initialization functions '''
        self._load_conf()
        wan_ip = ni.ifaddresses(self.get_conf('ACT_IF'))[ni.AF_INET][0]['addr']
        self.rt_vars['ipaddr'] = wan_ip
        script = self._scrape_homepage()
        if script:
            self._scrape_script(script)
        if 'remote' not in self.cookies:
            self.cookies['remote'] = wan_ip
        self._load_token()
        self.rt_vars['b64user'] = self._encrypt(self.get_conf('USERID').encode('utf-8'))
        self.rt_vars['b64pass'] = self._encrypt(self.get_conf('PASSWORD').encode('utf-8'))

    def check_valid_user(self):
        '''
        check if user is valid. the ACT portal does this before login,
        but it doesn't appear necessary.
        '''
        url = f"{self.ACT_BASEURL}/v1/subscriberdetails/profile/checkValidUser"
        data = { "userId": f"{self.rt_vars['b64user']}" }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            retdata['accountNo'] = self._decrypt(retdata['accountNo'])
            retdata['message'] = self._decrypt(retdata['message'])
            retdata['errorCode'] = self._decrypt(retdata['errorCode'])
            retdata['status'] = self._decrypt(retdata['status'])
            self._dprint(2, f"Data: {retdata}")
        return response.status_code

    def login_by_userid(self):
        ''' login using the user-id and password provided by ACT. '''
        url = f"{self.ACT_BASEURL}/v1/subscriberlogin/loginByUserId"
        data = {
            "userId": f"{self.rt_vars['b64user']}",
            "userPwd": f"{self.rt_vars['b64pass']}",
            "networkType": "ACT",
            "subscriberLoc": "",
            "remoteIP": f"{self.rt_vars['ipaddr']}",
            "ecType": ""
        }
        self._dprint(3, url, data, self.cookies)
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            retdata['errorCode'] = self._decrypt(retdata['errorCode'])
            self._dprint(2, f"Data: {retdata}")
        return response.status_code

    # TODO: Not used anymore. Pending removal
    def old_authenticate(self):
        ''' get a JWT token. This is required by some of the functions on the portal. '''
        url = f"{self.ACT_BASEURL}/v1/jwt/authenticate"
        plain_authkey = self.rt_vars['authkey']
        b64authkey = self._encrypt(plain_authkey.encode('utf-8'))
        plain_source = f"selfcare_{self.get_conf('USERID')}"
        b64source = self._encrypt(plain_source.encode('utf-8'))
        data = {
            "source": b64source,
            "authKey": b64authkey
        }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            self._dprint(2, retdata)
            jwt_token = retdata['jwtToken']
            output = jwt.decode(jwt_token, plain_authkey,
                        algorithms=["HS256", "HS384", "HS512"],
                        options={ "verify_signature": False })
            self._dprint(2, output)
            self.rt_vars['jwtToken'] = jwt_token
            self.rt_vars['jwt_exp'] = output['exp']
            with open(self.ACT_TOKENFILE, 'wb') as tokenfile:
                tokenfile.write(jwt_token.encode('utf-8'))
        return response.status_code

    def check_status(self, refresh_token = False):
        ''' this checks status and gets us a JWT token '''

        if 'ectype' not in self.rt_vars:
            self.connection_info()
        url = f"{self.ACT_BASEURL}/v1/subscriberlogin/checkStatus"
        req_headers = self.headers.copy()
        if refresh_token:
            req_headers['Authorization'] = f"Bearer {self.rt_vars['jwtToken']}"
            req_headers['isRefreshToken'] = "true"
        data = {
            "ecType": f"{self.rt_vars['ectype']}",
            "networkType": "ACT",
            "remoteIP": f"{self.rt_vars['ipaddr']}",
            "subscriberLoc": f"{self.rt_vars['city']}",
        }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            retdata['accountNo'] = self._decrypt(retdata['accountNo'])
            retdata['userName'] = self._decrypt(retdata['userName'])
            print(retdata)
            jwt_token = retdata['authToken']
            output = jwt.decode(jwt_token, self.rt_vars['authkey'],
                        algorithms=["HS256", "HS384", "HS512"],
                        options={ "verify_signature": False })
            
            # output['custDetails'] = self._decrypt(output['custDetails'])
            self._dprint(2, output)
            self.rt_vars['jwtToken'] = jwt_token
            self.rt_vars['jwt_exp'] = output['exp']
            with open(self.ACT_TOKENFILE, 'wb') as tokenfile:
                tokenfile.write(jwt_token.encode('utf-8'))
        return response.status_code

    def refresh_token(self):
        ''' Refresh the JWT token. This is a GET call. '''
        url = f"{self.ACT_BASEURL}/v1/jwt/refreshtoken"
        req_headers = self.headers.copy()
        req_headers['Authorization'] = f"Bearer {self.rt_vars['jwtToken']}"
        req_headers['isRefreshToken'] = "true"
        response = requests.get(url, cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            self._dprint(2, retdata)
            jwt_token = retdata['jwtToken']
            plain_authkey = self.rt_vars['authkey']
            output = jwt.decode(jwt_token, plain_authkey,
                        algorithms=["HS256", "HS384", "HS512"],
                        options={ "verify_signature": False })
            self._dprint(2, output)
            self.rt_vars['jwtToken'] = jwt_token
            self.rt_vars['jwt_exp'] = output['exp']
            with open(self.ACT_TOKENFILE, 'wb') as tokenfile:
                tokenfile.write(jwt_token.encode('utf-8'))
        return response.status_code

    def _fetch_token(self, force_refresh=False):
        '''
        check if we have a valid token and return it,
        else call authenticate or refresh_token to get a fresh one.
        '''
        now = int(time.time())
        expiry = self.rt_vars.get('jwt_exp', 0)
        retcode = 200
        if expiry < now + 2:
            retcode =  self.check_status()
        elif force_refresh or expiry < now + 30:
            retcode = self.refresh_token()
        return retcode

    def get_token(self, force_refresh=False):
        ''' Do a _fetch_token and then return the stored value '''
        self._fetch_token(force_refresh)
        return self.rt_vars['jwtToken']


    def user_info(self, silent):
        '''
        get user information. This also gets the user city, which is needed in other functions,
        so we call it silently if we need to use it for that purpose
        '''
        url = f"{self.ACT_BASEURL}/profile/userInfo"
        req_headers = self.headers.copy()
        req_headers['Authorization'] = f"Bearer {self.get_token()}"
        data = { "accountNo": f"{self.rt_vars['b64user']}" }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            self.rt_vars['city'] = retdata['city']
            self.rt_vars['b64phone'] = retdata['cellulerPhoneNo'] # Typo is on ACT's side.
            retdata['userId'] = self._decrypt(retdata['userId'])
            retdata['accountNo'] = self._decrypt(retdata['accountNo'])
            retdata['streetAddress'] = self._decrypt(retdata['streetAddress'])
            retdata['secAddress'] = self._decrypt(retdata['secAddress'])
            retdata['emailAddress'] = self._decrypt(retdata['emailAddress'])
            retdata['fullName'] = self._decrypt(retdata['fullName'])
            retdata['cellulerPhoneNo'] = self._decrypt(retdata['cellulerPhoneNo'])
            self._dprint(silent, retdata)
        return response.status_code

    def encoded_auth_token(self):
        ''' the ACT portal does this but we don't seem to use it. Included for completeness '''
        url = f"{self.ACT_BASEURL}/v1/servicerequest/encodedAuthToken"
        req_headers = self.headers.copy()
        req_headers['Authorization'] = f"Bearer {self.get_token()}"
        data = {
            "accountNo": f"{self.rt_vars['b64user']}",
            "userId": f"{self.rt_vars['b64user']}"
        }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            retdata['authtext'] = self._decrypt(retdata['authtext'])
            retdata['token'] = self._decrypt(retdata['token'])
            print(retdata)
        return response.status_code

    def connection_info(self):
        '''
            get information about this connection
            This is required to get other info
        '''
        url = f"{self.ACT_BASEURL}/ippool/connectionInfo"
        data = { "location": f"self.rt_vars['ipaddr']" }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            self._dprint(1, retdata)
            self.rt_vars['city'] = retdata['subscriberLoc']
            self.rt_vars['location'] = retdata['locationCode']
            self.rt_vars['ectype'] = retdata['ecType']
            return retdata
        return None

    def location_details(self, city):
        '''
        get information about ACT infra for a city.
        This is required to get usage and plan info
        '''
        url = f"{self.ACT_BASEURL}/v1/ippool/locationDetails"
        data = { "location": city }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=self.headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            self._dprint(1, retdata)
            return retdata
        return None

    def usage_details(self):
        ''' get usage information for this account '''
        if 'city' not in self.rt_vars:
            self.user_info(1)
        locinfo = self.location_details(self.rt_vars['city'])
        url = f"{self.ACT_BASEURL}/v1/user/usage/usageDetails/"
        req_headers = self.headers.copy()
        req_headers['Authorization'] = f"Bearer {self.get_token()}"
        data = {
            "accountNo": f"{self.rt_vars['b64user']}",
            "userId": f"{self.rt_vars['b64user']}",
            "phone": f"{self.rt_vars['b64phone']}",
            "location": locinfo['locationCode'],
            "ecType": locinfo['ecType']
        }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            print(retdata)
        return response.status_code

    def agreement_info(self):
        ''' get the plan details for this account '''
        url = f"{self.ACT_BASEURL}/v1/user/usage/agreementInfo"
        req_headers = self.headers.copy()
        req_headers['Authorization'] = f"Bearer {self.get_token()}"
        data = {
            "accountNo": f"{self.rt_vars['b64user']}",
            "userId": f"{self.rt_vars['b64user']}",
            "ecType": "",
            "location": "",
            "mobileNo": ""
        }
        response = requests.post(url, data=json.dumps(data),
                        cookies=self.cookies, headers=req_headers)
        self._dprint(1, f"{url}: Status {response.status_code}")
        if response.status_code == 200:
            retdata = response.json()
            print(retdata)
        return response.status_code

    def do_service_loop(self, sleep_time=120):
        '''
        Login and then continuously refresh JWT Token,
        similar to how the ACT homepage works.
        This method is compatible with running as a systemd service.
        '''
        retcode = self.login_by_userid()
        while retcode == 200:
            retcode = self._fetch_token(force_refresh=True)
            time.sleep(sleep_time)
        self._dprint(1, f"Service loop exited with retcode {retcode}")
        return retcode

def _main():
    '''
    Code to exercise all key abilities of ACTConnection and interact with ACT broadband.
    '''
    parser = argparse.ArgumentParser(description='Interact with ACT Broadband Service')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                    help='Be verbose. Repeat for even more verbosity (e.g. -vvv)')
    parser.add_argument('-c', '--check', action='store_true',
                    help='check if user is valid')
    parser.add_argument('-C', '--conn', action='store_true',
                    help='check connection info')
    parser.add_argument('-s', '--status', action='store_true',
                    help='check status')
    parser.add_argument('-l', '--login', action='store_true',
                    help='Log in to ACT Broadband account')
    parser.add_argument('-r', '--refresh', action='store_true',
                    help='Refresh JWT Token, logging in if required.')
    parser.add_argument('-i', '--info', action='store_true',
                    help='Retrieve Account User Information')
    parser.add_argument('-u', '--usage', action='store_true',
                    help='Retrieve Usage Details')
    parser.add_argument('-p', '--plan', action='store_true',
                    help='Retrieve Plan Details')
    parser.add_argument('-S', '--service', action='store_true',
                    help='Run continuously (systemd service compatible)')
    args = parser.parse_args()

    conn = ACTConnection(args.verbose)

    conn.initialize()


    if args.check:
        conn.check_valid_user()

    if args.conn:
        conn.connection_info()

    if args.status:
        conn.check_status()

    if args.login:
        conn.login_by_userid()

    if args.info:
        conn.user_info(0)

    if args.refresh:
        conn.get_token(force_refresh=True)

    if args.usage:
        conn.usage_details()

    if args.plan:
        conn.agreement_info()

    if args.service:
        conn.do_service_loop()

if __name__ == "__main__":
    _main()
