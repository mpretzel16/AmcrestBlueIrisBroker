# Copyright 2022 Michael Pretzel | Pretzel Bytes LLC
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished
#  to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import hashlib
import requests
import json
from threading import Thread
from time import sleep, time


class BlueIrisClient:
    str_server_url: str = ""  # Base URL for the BlueIris5 Server http://127.0.0.1:81
    str_username: str = ""  # BlueIris5 Admin User
    str_password: str = ""  # Password for the Above User
    str_session_id: str = ""  # BlueIris5 Generated Session ID
    float_session_start_time: float = 0  # Timestamp of Session Start
    bool_logged_in: bool = False  # BlueIris5 Success Authentication
    bool_request_exit: bool = False  # Program Requested Exit, Kill Threads
    bool_rolling_session_id: bool = False  # In Process of Getting New Session ID
    int_server_status: int = 0

    # Initialize the Class, Set Global Variables, Login, Start Session Checker
    def __init__(self, str_url: str, str_username: str, str_password: str):
        if not str_url.endswith("/"):
            str_url = str_url + "/"
        self.str_server_url = str_url
        self.str_username = str_username
        self.str_password = str_password
        dict_result_login = self.login()
        if not dict_result_login['bool_error']:
            if dict_result_login['bool_logged_in']:
                self.bool_logged_in = True
                print("Logged In")
                thread_session_checker = Thread(target=self.check_session)
                thread_session_checker.start()
                # requests_request = self.send_bi_http_command("image/FrontDoor?decode=1&q=100")
        else:
            print(dict_result_login['str_status'])

    # Logout and Request Thread Exit
    def exit(self):
        self.send_bi_json_command({"cmd": "logout"})
        self.bool_request_exit = True

    # Logout of Current Session and Start a New Session
    def roll_session_id(self):
        try:
            self.bool_rolling_session_id = True
            dict_result_logout: dict = self.send_bi_json_command({"cmd": "logout"})
            if not dict_result_logout['bool_error']:
                if dict_result_logout['bi_result']['result'] == "success":
                    self.bool_logged_in = False
                    self.str_session_id = ""
                    self.float_session_start_time = 0
                    dict_result_login: dict = self.login()
                    if not dict_result_login['bool_error']:
                        if dict_result_login['bool_logged_in']:
                            self.bool_rolling_session_id = False
                        else:
                            self.bool_rolling_session_id = False
                    else:
                        self.bool_rolling_session_id = False
                else:
                    self.bool_rolling_session_id = False
            else:
                self.bool_rolling_session_id = False
        except Exception as e:
            print(e)

    # Login to BlueIris5
    def login(self):
        dict_return = dict()
        dict_return['bool_error']: bool = False
        dict_return['str_status']: str = None
        dict_return['bool_logged_in']: bool = False
        try:
            dict_bi_login_command = dict()
            dict_bi_login_command["cmd"] = "login"
            result_get_session_id = self.send_bi_json_command(dict_bi_login_command)
            if not result_get_session_id['bool_error']:
                if not result_get_session_id['bi_result'] is None:
                    result_get_session_id_bi_result: dict = result_get_session_id['bi_result']
                    if result_get_session_id_bi_result['result'] == 'fail':
                        result_get_session_id_bi_result_data: dict = result_get_session_id_bi_result['data']
                        if result_get_session_id_bi_result_data['reason'] == "missing response":
                            self.str_session_id = result_get_session_id_bi_result['session']
                            str_hash: str = "{}:{}:{}".format(self.str_username, self.str_session_id, self.str_password)
                            byte_hash: bytes = str_hash.encode('utf-8')
                            str_send_hash: str = hashlib.md5(byte_hash).hexdigest()
                            dict_bi_login_command["response"] = str_send_hash
                            result_attempt_login = self.send_bi_json_command(dict_bi_login_command)
                            if not result_attempt_login['bool_error']:
                                if not result_attempt_login['bi_result'] is None:
                                    result_attempt_login_bi_result: dict = result_attempt_login['bi_result']
                                    if result_attempt_login_bi_result['result'] == 'success':
                                        dict_return['bool_logged_in'] = True
                                        self.float_session_start_time = time()
                                        result_attempt_login_bi_result_bi_result_data: dict = \
                                            result_attempt_login_bi_result['data']
                                    else:
                                        dict_return['bool_error'] = True
                                        dict_return['str_status'] = "Blue Iris Login Failed '{}'".format(
                                            result_attempt_login_bi_result['reason'])
                            else:
                                dict_return['bool_error'] = True
                                dict_return['str_status'] = result_attempt_login['str_status']
                        else:
                            dict_return['bool_error'] = True
                            dict_return['str_status'] = "Expecting 'missing response' got '{}'".format(
                                result_get_session_id_bi_result_data['reason'])
                    else:
                        dict_return['bool_error'] = True
                        dict_return['str_status'] = "Unexpected Response From Blue Iris"
                else:
                    dict_return['bool_error'] = True
                    dict_return['str_status'] = "No Result Received From Blue Iris"
            else:
                dict_return['bool_error'] = True
                dict_return['str_status'] = result_get_session_id['str_status']
        except Exception as e:
            dict_return['bool_error'] = True
            dict_return['str_status'] = str(e)
        return dict_return

    # Verify that 'success' is returned from BlueIris5
    def check_session(self):
        while True and not self.bool_request_exit:
            float_current_time: float = time()
            float_time_diff: float = float_current_time - self.float_session_start_time
            if float_time_diff >= 86400:
                print("Roll Key")
                self.roll_session_id()
            if self.bool_rolling_session_id:
                sleep(10)
                continue
            dict_cmd: dict = dict()
            dict_cmd['cmd']: str = "status"
            
            # print("Checking Session {}".format(self.str_session_id))
            try:
                if not self.bool_logged_in:
                    self.login()
                dict_result: dict = self.send_bi_json_command(dict_cmd)
                if not dict_result['bool_error']:
                    dict_bi_result: dict = dict_result['bi_result']
                    self.int_server_status = dict_bi_result['data']['signal']
                    if dict_bi_result['result'] == "fail":
                        self.login()
                else:
                    print("Error {}".format(dict_result['str_status']))
                del dict_result
                del dict_bi_result
            except Exception as e:
                print(str(e))
            sleep(10)
        print("I do an Exit")

    # Send a JSON API command to BlueIris5
    def send_bi_json_command(self, dict_cmd: dict):
        dict_return = dict()
        dict_return['bool_error']: bool = False
        dict_return['str_status']: str = None
        dict_return['bi_result']: dict = {}
        try:
            dict_cmd['session'] = self.str_session_id
            result_request = requests.post("{}json".format(self.str_server_url), data=json.dumps(dict_cmd))
            if result_request.status_code == 200:
                result = result_request.json()
                dict_return['bi_result'] = result
            else:
                dict_return['bool_error'] = True
                dict_return['str_status'] = "Unexpected URL Status Code: {}".format(result_request.status_code)
        except Exception as e:
            dict_return['bool_error'] = True
            dict_return['str_status'] = str(e)
        return dict_return

    # Send a HTTP Command to BlueIris5 (i.e. Get Image From Camera)
    def send_bi_http_command(self, str_url: str):
        dict_return = dict()
        dict_return['bool_error']: bool = False
        dict_return['str_status']: str = None
        dict_return['bi_result']: requests.models.Response = None
        try:
            cookies = {'session': self.str_session_id}

            result = requests.get("{}{}".format(self.str_server_url, str_url), cookies=cookies)
            if result.status_code == 200:
                dict_return['bi_result'] = result
            else:
                dict_return['bool_error'] = True
                dict_return['str_status'] = "Invalid HTTP Status Code. Expected 200, got: {}".format(result.status_code)
        except Exception as e:
            dict_return['bool_error'] = True
            dict_return['str_status'] = str(e)
        return dict_return

    def process(self):
        while True and not self.bool_request_exit:
            print("HI {}".format(self.str_session_id))
            sleep(5)
