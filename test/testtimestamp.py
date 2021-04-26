import fileinput,sys
import json
from pprint import pprint
from elasticsearch import Elasticsearch
from datetime import datetime

es = Elasticsearch(['127.0.0.1'],port=9200)


f1 = fileinput.input(files=sys.argv[1])
f2 = fileinput.input(files=sys.argv[2])



Login_Fail = {}
Multiple_LoginList = []
Multiple_Login = {}
LoginActionList = []
LoginAction = {}
CaptiveAction = {}
CaptiveActionList = []
Alert = {}
RawLog = {}
TimePeriod = 60000


while True:
    CaptiveLog = f2.readline()
    if not CaptiveLog:
        break
    CaptiveLog = CaptiveLog.split(' ')
    CaptiveTimestamp = CaptiveLog[0][:10]
    CaptiveStatus = CaptiveLog[5]
    LoginUsername = CaptiveLog[2].lower()
    LoginDomain = CaptiveLog[1]
    IPv4 = CaptiveLog[3]
    IPv6 = CaptiveLog[4]
    timestamp = datetime.fromtimestamp(int(CaptiveTimestamp)).isoformat()
    
    if CaptiveStatus == "access":
        pass
    if not LoginUsername in Login_Fail.keys():
        Login_Fail[LoginUsername] = {"S":0,"F":0,"FStreak":0,"MaxStreak":0,"Alert": False}
    if CaptiveStatus == "success":
        Login_Fail[LoginUsername]['S'] +=1
        Login_Fail[LoginUsername]['FStreak'] = 0
        Login_Fail[LoginUsername]['Alert'] = False
    elif CaptiveStatus == "fail":
        Login_Fail[LoginUsername]['F'] +=1
        Login_Fail[LoginUsername]['FStreak'] += 1
        if Login_Fail[LoginUsername]['FStreak'] > Login_Fail[LoginUsername]['MaxStreak']:
            Login_Fail[LoginUsername]['MaxStreak'] = Login_Fail[LoginUsername]['FStreak']
        if ((Login_Fail[LoginUsername]['FStreak'] > 5) and (Login_Fail[LoginUsername]['Alert'] == False)):
            Login_Fail[LoginUsername]['Alert'] = True
            Alert = {
                "Alert_Type": "Excessive Failed Login", 
                "@timestamp": timestamp, 
                "Username": LoginUsername, 
                "MACAddress": "-", 
                "IPv4": IPv4, 
                "IPv6": IPv6
                }
            es.index(index='testalertlog',timestamp=timestamp, body=Alert)
    

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
        
    timestamp = datetime.fromtimestamp(int(Log_Timestamp)).isoformat()
    
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
            if (IPaddress in Multiple_Login[LoginUsername]["NowLogin"]):
                Multiple_Login[LoginUsername]["NowLogin"].remove(LoginLog[5])
            if (len(Multiple_Login[LoginUsername]["NowLogin"]) == 0):
                Multiple_Login[LoginUsername]["Area"] = 0
        elif (LoginStatus == "login-page") or (LoginStatus == "autologin") or (LoginStatus == "RE_LOGIN") or (LoginStatus == "sso-page"):
            if (len(Multiple_Login[LoginUsername]["NowLogin"]) == 0):
                if LoginLog[5] != "-":
                    if (IPaddress[0] == "158"):
                        Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[2]/64)) + 1
                        Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                    elif (IPaddress[0] == "10"):
                        Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[1]/64)) + 1
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
                                "Alert_Type": "Login From Multiple Locations", 
                                "@timestamp": timestamp, 
                                "Username": LoginUsername, 
                                "MACAddress": MAC_Address, 
                                "IPv4": IPv4, 
                                "IPv6": IPv6
                                }
                            es.index(index='testalertlog', timestamp=timestamp, body=Alert)
                            Multiple_Login[LoginUsername]["NowLogin"] = []
                            Multiple_Login[LoginUsername]["Area"] = 0
                    elif (IPaddress[0] == "10"):
                        if (int(int(IPaddress[1])/64) + 1 == Multiple_Login[LoginUsername]["Area"]):
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                        else:
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                            Alert = {
                                "Alert_Type": "Login From Multiple Locations", 
                                "@timestamp": timestamp, 
                                "Username": LoginUsername, 
                                "MACAddress": MAC_Address, 
                                "IPv4": IPv4, 
                                "IPv6": IPv6
                                }
                            es.index(index='testalertlog', timestamp=timestamp, body=Alert)
                            Multiple_Login[LoginUsername]["NowLogin"] = []
                            Multiple_Login[LoginUsername]["Area"] = 0