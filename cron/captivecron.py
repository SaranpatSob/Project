import fileinput,sys
import os,shutil
import json
from elasticsearch import Elasticsearch
from datetime import datetime
import time

es = Elasticsearch(['127.0.0.1'],port=9200)


Login_Fail = {}
CaptiveAction = {}
CaptiveActionList = []
Alert = {}
RawLog = {}
TimePeriod = 60000

filepath = '/home/admin/cron/captivelog/'
archive = '/home/admin/cron/archived_captivelog/'
entries = os.listdir(filepath)
for entry in entries:
    f2 = open(filepath+entry, "r")
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


        ttime = time.time()
        dtime = datetime.utcfromtimestamp(int(ttime)).strftime('%Y.%m.%d')
        timestamp = datetime.fromtimestamp(int(ttime)).isoformat()
        _index = "so-import-"+dtime


        RawLog = {
            "@timestamp": timestamp, 
            "user.name": LoginUsername, 
            "ipv4": IPv4, 
            "ipv6": IPv6, 
            "log.action": CaptiveStatus,
            "log.source": "captivelog" 
            }
        es.index(index=_index, body=RawLog)
        
        if LoginUsername == "-":
            continue

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
            if ((Login_Fail[LoginUsername]['FStreak'] >= 10) and (Login_Fail[LoginUsername]['Alert'] == False)):
                Login_Fail[LoginUsername]['Alert'] = True
                Alert = {
                    "@timestamp": timestamp, 
                    "alert.type": "Excessive Failed Login",  
                    "user.name": LoginUsername, 
                    "ipv4": IPv4, 
                    "ipv6": IPv6, 
                    "log.action": CaptiveStatus,
                    "detected.by": "loganalyzer",
                    "log.source": "captivelog" 
                    }
                es.index(index=_index, body=Alert)
    shutil.move(filepath+entry, archive)
