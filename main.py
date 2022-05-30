# !/usr/bin/env python3
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

import threading
import time
from datetime import datetime
import urllib.parse
import requests
from pyftpdlib import servers
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
import os
import yaml
from paho.mqtt import client as mqtt_client
from blue_iris_client import BlueIrisClient
from loguru import logger

class BITrigger():
    use_mqtt = False
    mqtt_conn: mqtt_client.Client
    mqtt_topic = "BlueIris/admin"
    use_api = False
    use_secure = False
    bi_client: BlueIrisClient
    str_nonsecure_url = None
    def __init__(self, dict_bi_config: dict):
        use_mqtt = False
        use_api = False
        if 'mqtt' in dict_bi_config:
            use_mqtt = True
        elif 'api' in dict_bi_config:
            use_api = True
        else:
            exit(1)
        if use_mqtt:
            self.use_mqtt = True
            mqtt = dict_bi_config['mqtt']
            broker = mqtt['server']
            port = mqtt['port']
            client = 'AmcrestBlueIrisBroker'
            if 'user' in mqtt and 'password' in mqtt:
                username = mqtt['user']
                password = mqtt['password']
            else:
                username = None
                password = None
            self.mqtt_conn = self.connect_mqtt(client, username, password, broker, port)
        elif use_api:
            self.use_api = True
            api = dict_bi_config['api']
            if api['use_secure_session_keys']:
                self.use_secure = True
                bi_client = BlueIrisClient("{protocol}://{server}:{port}"
                                           .format(protocol=api['protocol'],
                                                   server=api['server'],
                                                   port=api['port']),
                                           api['user'],
                                           api['password'])
                self.bi_client = bi_client
            else:
                username = api['user']
                password = api['password']
                username = urllib.parse.quote(username)
                password = urllib.parse.quote(password)
                url = "{protocol}://{username}:{password}@{server}:{port}" \
                    .format(username=username,
                            password=password,
                            protocol=api['protocol'],
                            server=api['server'],
                            port=api['port'])
                self.str_nonsecure_url = url

    def connect_mqtt(self, client_id, username, password, broker, port):
        print("Conn")
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print("Connected to MQTT Broker!")
            else:
                print("Failed to connect, return code %d\n", rc)

        # Set Connecting Client ID
        client = mqtt_client.Client(client_id)
        if not username is None and not password is None:
            print("pass")
            client.username_pw_set(username, password)
        client.on_connect = on_connect
        client.connect(broker, port)
        return client

    def publish(self, client, topic, msg):
        result = client.publish(topic, msg)
        status = result[0]
        if status == 0:
            print(f"Send `{msg}` to topic `{topic}`")
        else:
            print(f"Failed to send message to topic {topic}")

    def trigger(self, bi_camera_name: str):
        if self.use_mqtt:
            self.publish(self.mqtt_conn,
                         self.mqtt_topic,
                         "camera={cameraName}&trigger".format(cameraName=bi_camera_name))
        elif self.use_api:
            if self.use_secure:
                print("BI Trigger")
                t = self.bi_client.send_bi_json_command({"cmd": "trigger",
                                                         "session": self.bi_client.str_session_id,
                                                         "camera": bi_camera_name,
                                                         "memo": "Trigger from Amcrest Camera"})
            else:
                requests.get("{url}/admin?camera={camera}&trigger&memo={memo}"
                             .format(url=self.str_nonsecure_url,
                                     camera=bi_camera_name, memo="Trigger from Amcrest Camera"))


class CustomFTPHandler(FTPHandler):
    dict_current_alerting = {}
    def on_file_received(self, file: str):
        def process_request():
            if file.endswith(".jpg") or file.endswith(".jpeg"):
                image_directory = '{}\image_dir'.format(script_dir)
                new_file = file.replace(image_directory, '')
                if "\\" in new_file:
                    camera_name = new_file.split("\\")[1]
                else:
                    camera_name = new_file.split("/")[1]
                print(camera_name)
                dict_camera = dict_cameras[camera_name]
                if camera_name in self.dict_current_alerting:
                    alert_time = self.dict_current_alerting[camera_name]
                    if datetime.utcnow().timestamp() >= alert_time + dict_camera['retrigger_time']:
                        bi_trigger.trigger(dict_camera['bi_camera_name'])
                else:
                    self.dict_current_alerting[camera_name] = datetime.utcnow().timestamp()
                    bi_trigger.trigger(dict_camera['bi_camera_name'])
                print(self.dict_current_alerting)
            self.add_channel()

        self.del_channel()
        threading.Thread(target=process_request).start()


def check_configuration(dict_config):
    print(dict_config)
    try:
        bool_error = False
        if 'cameras' in dict_config:
            if len(dict_config['cameras']) > 0:
                for camera in dict_config['cameras']:
                    if not 'bi_camera_name' in dict_config['cameras'][camera]:
                        logger.error("bi_camera_name not in cameras.{}".format(camera))
                        bool_error = True
                    if not 'retrigger_time' in dict_config['cameras'][camera]:
                        logger.error("retrigger_time not in cameras.{}".format(camera))
                        bool_error = True
            else:
                logger.error("cameras does not contain any cameras")
                bool_error = True
        else:
            logger.error("cameras is required in config.yml")
            bool_error = True

        if 'blue_iris_config' in dict_config:
            if not 'mqtt' in dict_config['blue_iris_config'] and\
                    not 'api' in dict_config['blue_iris_config']:
                logger.error("Either mqtt or api required within blue_iris_config in config.yml")
                bool_error = True
            else:
                if 'mqtt' in dict_config['blue_iris_config'] and \
                        'api' in dict_config['blue_iris_config']:
                    logger.warning("mqtt and api exist within blue_iris_config in config.yml. mqtt will be used")
                    if not 'server' in dict_config['blue_iris_config']['mqtt']:
                        logger.error("server required within blue_iris_config.mqtt in config.yml")
                        bool_error = True
                    if not 'port' in dict_config['blue_iris_config']['mqtt']:
                        logger.error("port required within blue_iris_config.mqtt in config.yml")
                        bool_error = True
                else:
                    if 'mqtt' in dict_config['blue_iris_config']:
                        if not 'server' in dict_config['blue_iris_config']['mqtt']:
                            logger.error("server required within blue_iris_config.mqtt in config.yml")
                            bool_error = True
                        if not 'port' in dict_config['blue_iris_config']['mqtt']:
                            logger.error("port required within blue_iris_config.mqtt in config.yml")
                            bool_error = True
                    elif 'api' in dict_config['blue_iris_config']:
                        if not 'protocol' in dict_config['blue_iris_config']['api']:
                            logger.error("protocol required within blue_iris_config.api in config.yml")
                            bool_error = True
                        if not 'server' in dict_config['blue_iris_config']['api']:
                            logger.error("server required within blue_iris_config.api in config.yml")
                            bool_error = True
                        if not 'port' in dict_config['blue_iris_config']['api']:
                            logger.error("port required within blue_iris_config.api in config.yml")
                            bool_error = True
                        if not 'user' in dict_config['blue_iris_config']['api']:
                            logger.error("user required within blue_iris_config.api in config.yml")
                            bool_error = True
                        if not 'password' in dict_config['blue_iris_config']['api']:
                            logger.error("password required within blue_iris_config.api in config.yml")
                            bool_error = True
                        if not 'use_secure_session_keys' in dict_config['blue_iris_config']['api']:
                            logger.error("use_secure_session_keys required within blue_iris_config.api in config.yml")
                            bool_error = True
                    else:
                        logger.error("mqtt and\or api not within blue_iris_config.mqtt in config.yml")
                        bool_error = True


        else:
            logger.error("blue_iris_config is required in config.yml")
            bool_error = True

        if 'ftp_server' in dict_config:
            if not 'protocol' in dict_config['ftp_server']['listen_address']:
                logger.error("listen_address required within ftp_server in config.yml")
                bool_error = True
            if not 'server' in dict_config['ftp_server']['listen_port']:
                logger.error("listen_port required within ftp_server in config.yml")
                bool_error = True
            if not 'port' in dict_config['ftp_server']['use_anonymous_user']:
                logger.error("use_anonymous_user required within ftp_server in config.yml")
                bool_error = True
            if 'users' in dict_config['ftp_server']:
                if len(dict_config['ftp_server']['users']) == 0 and \
                    dict_config['ftp_server']['use_anonymous_user'] == False:
                    logger.error("No users configured and use_anonymous_user=False within ftp_server in config.yml")
                    bool_error = True
            elif not 'users' in dict_config['ftp_server'] and \
                    dict_config['ftp_server']['use_anonymous_user'] == False:
                    logger.error("No users configured and use_anonymous_user=False within ftp_server in config.yml")
                    bool_error = True
            if 'users' in dict_config['ftp_server']:
                for user in dict_config['ftp_server']['users']:
                    


        else:
            logger.error("ftp_server is required in config.yml")
            bool_error = True
    except Exception as e:
        logger.error("Error checking configuration: {error}".format(error=str(e)))
        bool_error = True
    if bool_error:
        exit(1)
    else:
        return True

if __name__ == '__main__':
    logger.add("logs/AmcrestBlueIrisBroker_{time:YYYYMMDD}.log",
               enqueue=True,
               serialize=True,
               level="DEBUG",
               rotation="00:00")
    script_dir = os.path.dirname(os.path.realpath(__file__))
    dict_config_info = {}
    dict_cameras = {}
    logger.debug("Loading config.yml")
    try:
        with open("config.yml", "r") as stream:
            try:
                dict_config_info = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                logger.error("Unable to load config.yml: {error}".format(error=str(exec)))
                exit(1)
    except Exception as e:
        logger.error("Unable to load config.yml: {error}".format(error=str(e)))
        exit(1)
    logger.debug("config.yml successfully loaded")
    check_configuration(dict_config_info)
    # bi_trigger = BITrigger(dict_config_info['blue_iris_config'])
    # dict_cameras = dict_config_info['cameras']
    # authorizer = DummyAuthorizer()
    # if not dict_config_info['ftp_server']['use_anonymous_user']:
    #     for user in dict_config_info['ftp_server']['users']:
    #         user = user['user']
    #         authorizer.add_user(user['username'], user['password'], '{}/image_dir'.format(script_dir), perm='elradfmwMT')
    # else:
    #     authorizer.add_anonymous('{}/image_dir'.format(script_dir), perm='elradfmwMT')
    # address = (dict_config_info['ftp_server']['listen_address'],
    #            dict_config_info['ftp_server']['listen_port'])
    # handler = CustomFTPHandler
    # handler.authorizer = authorizer
    # server = servers.FTPServer(address, handler)
    #
    # server.serve_forever()


