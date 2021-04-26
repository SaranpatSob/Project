import fileinput,sys
import json
from pprint import pprint
from elasticsearch import Elasticsearch
from datetime import datetime
import time

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
    CaptiveTimestamp = CaptiveLog[0][:13]
    CaptiveStatus = CaptiveLog[5]
    LoginUsername = CaptiveLog[2].lower()
    LoginDomain = CaptiveLog[1]
    IPv4 = CaptiveLog[3]
    IPv6 = CaptiveLog[4]

    time = int(time.time())
    timestamp = datetime.fromtimestamp(time).isoformat()

    RawLog = {
        "@timestamp": timestamp, 
        "user.name": LoginUsername, 
        "ipv4": IPv4, 
        "ipv6": IPv6, 
        "status": CaptiveStatus,
        "log.source": "captivelog" 
        }
    es.index(index='so-import-2020.12.15', body=RawLog)
    

while True:
    LoginLog = f1.readline()
    if not LoginLog:
        break
    LoginLog = LoginLog.split(' ')
    LoginUser = LoginLog[2].split('@')
    LoginUsername = LoginUser[0].lower()
    LoginStatus = LoginLog[8]
    Login_Timestamp = LoginLog[1][:13]
    Logout_Timestamp = LoginLog[3][:13]
    MAC_Address = LoginLog[4]
    IPv4 = LoginLog[5]
    IPv6 = LoginLog[6]

    time = int(time.time())
    timestamp = datetime.fromtimestamp(time).isoformat()

    RawLog = {
        "@timestamp": timestamp, 
        "user.name": LoginUsername, 
        "ipv4": IPv4, 
        "ipv6": IPv6, 
        "status": LoginStatus, 
        "log.source": "loginlog"
        }
    es.index(index='so-import-2020.12.15', body=RawLog)
    
    
    


# es = Elasticsearch(['127.0.0.1'],port=9200)

# timestamp = datetime.fromtimestamp(int(1607072267)).isoformat()

# Alert = {
#             "Alert_Type": "Excessive Failed Login", 
#             "@timestamp": timestamp, 
#             "Username": "sfscitnp", 
#             "MACAddress": "-", 
#             "IPv4": "158.108.33.56", 
#             "IPv6": "-"
#             }
# es.index(index='testalertlog', body=Alert)

# timestamp = datetime.fromtimestamp(int(1607072268)).isoformat()

# Alert = {
#             "Alert_Type": "Excessive Failed Login", 
#             "@timestamp": timestamp, 
#             "Username": "b6140402097", 
#             "MACAddress": "-", 
#             "IPv4": "158.108.33.56", 
#             "IPv6": "-"
#             }
# es.index(index='testalertlog', body=Alert)