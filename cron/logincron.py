import fileinput,sys
import os,shutil
import json
from elasticsearch import Elasticsearch
from datetime import datetime
import time

es = Elasticsearch(['127.0.0.1'],port=9200)


Login_Fail = {}
Multiple_LoginList = []
Multiple_Login = {}
LoginActionList = []
LoginAction = {}
Alert = {}
RawLog = {}
TimePeriod = 60000

filepath = '/home/admin/cron/loginlog/'
archive = '/home/admin/cron/archived_loginlog/'
entries = os.listdir(filepath)
for entry in entries:
    f1 = open(filepath+entry, "r")
    while True:
        LoginLog = f1.readline()
        if not LoginLog:
            break
        LoginLog = LoginLog.split(' ')
        LoginUser = LoginLog[2].split('@')
        LoginUsername = LoginUser[0].lower()
        LoginStatus = LoginLog[8]
        Login_Timestamp = LoginLog[1][:10]
        Logout_Timestamp = LoginLog[3][:10]
        MAC_Address = LoginLog[4]
        IPv4 = LoginLog[5]
        IPv6 = LoginLog[6]

        if (LoginStatus == "TIMEOUT") or (LoginStatus == "force-logout") or (LoginStatus == "logout-all-page"):
            Log_Timestamp = Logout_Timestamp
        elif (LoginStatus == "login-page") or (LoginStatus == "autologin") or (LoginStatus == "RE_LOGIN") or (LoginStatus == "sso-page"):
            Log_Timestamp = Login_Timestamp
        

        ttime = time.time()
        dtime = datetime.utcfromtimestamp(int(ttime)).strftime('%Y.%m.%d')
        timestamp = datetime.fromtimestamp(int(ttime)).isoformat()
        _index = "so-import-"+dtime


        RawLog = {
            "@timestamp": timestamp, 
            "user.name": LoginUsername, 
            "ipv4": IPv4, 
            "ipv6": IPv6,
            "MAC.Address": MAC_Address,
            "log.action": LoginStatus, 
            "log.source": "loginlog"
            }
        es.index(index=_index, body=RawLog)
        
        
        IPaddress = LoginLog[5].split(".")
        if (not LoginUsername in Multiple_Login.keys()):
            if LoginLog[5] != "-":
                Multiple_Login[LoginUsername] = {"NowLogin":[],"Area":0}
                if (IPaddress[0] == "158"):
                    Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[2])/64) + 1
                    Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                elif (IPaddress[0] == "10"):
                    Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[1])/64) + 1
                    Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                else:
                    Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
            else:
                Multiple_Login[LoginUsername] = {"NowLogin":["-"],"Area":0}
                
        else:
            if (LoginStatus == "TIMEOUT") or (LoginStatus == "force-logout") or (LoginStatus == "logout-all-page"):
                if (IPv4 in Multiple_Login[LoginUsername]["NowLogin"]):
                    Multiple_Login[LoginUsername]["NowLogin"].remove(IPv4)
                if (len(Multiple_Login[LoginUsername]["NowLogin"]) == 0):
                    Multiple_Login[LoginUsername]["Area"] = 0
            elif (LoginStatus == "login-page") or (LoginStatus == "autologin") or (LoginStatus == "RE_LOGIN") or (LoginStatus == "sso-page"):
                if (len(Multiple_Login[LoginUsername]["NowLogin"]) == 0):
                    if LoginLog[5] != "-":
                        if (IPaddress[0] == "158"):
                            Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[2])/64) + 1
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                        elif (IPaddress[0] == "10"):
                            Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[1])/64) + 1
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                        else:
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                else:
                    if LoginLog[5] != "-":
                        if (IPaddress[0] == "158"):
                            if (int(int(IPaddress[2])/64) + 1 == Multiple_Login[LoginUsername]["Area"]):
                                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                            else:
                                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                                Alert = {
                                    "@timestamp": timestamp, 
                                    "alert.type": "Login From Multiple Locations",  
                                    "user.name": LoginUsername, 
                                    "ipaddress" : Multiple_Login[LoginUsername]["NowLogin"],
                                    "area" : [Multiple_Login[LoginUsername]["Area"],int(int(IPaddress[2])/64) + 1],
                                    "log.action": LoginStatus, 
                                    "detected.by": "loganalyzer",
                                    "log.source": "loginlog"
                                    }
                                es.index(index=_index, body=Alert)
                                Multiple_Login[LoginUsername]["NowLogin"] = []
                                Multiple_Login[LoginUsername]["Area"] = 0
                        elif (IPaddress[0] == "10"):
                            if (int(int(IPaddress[1])/64) + 1 == Multiple_Login[LoginUsername]["Area"]):
                                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                            else:
                                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                                Alert = {
                                    "@timestamp": timestamp, 
                                    "alert.type": "Login From Multiple Locations",  
                                    "user.name": LoginUsername, 
                                    "ipaddress" : Multiple_Login[LoginUsername]["NowLogin"],
                                    "area" : [Multiple_Login[LoginUsername]["Area"],int(int(IPaddress[1])/64) + 1],
                                    "log.action": LoginStatus, 
                                    "detected.by": "loganalyzer",
                                    "log.source": "loginlog"
                                    }
                                es.index(index=_index, body=Alert)
                                Multiple_Login[LoginUsername]["NowLogin"] = []
                                Multiple_Login[LoginUsername]["Area"] = 0
    shutil.move(filepath+entry, archive)
