import fileinput,sys,json,pymongo
from pprint import pprint
from elasticsearch import Elasticsearch
from datetime import datetime
import time


client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["phishing_website"]
col = db["phishing_domain"]
phish_data = list(col.find({},{"_id":0}))

es = Elasticsearch(['127.0.0.1'],port=9200)

f1 = fileinput.input(files=sys.argv[1])

RawLog = {}
Alert = {}
TimePeriod = 60
TimeStamp = 0

while True:
    WebLog = f1.readline()
    if not WebLog:
        break
    WebLog = WebLog.split(' ')
    if (WebLog[4] != '-'):
        WebUser = WebLog[4].split('@')
        WebUsername = WebUser[0].lower()
    else:
        WebUsername = '-'
    ReqTimestamp = int(WebLog[0][:10])
    FlowTimestamp = int(WebLog[2][:10])
    Session_ID = WebLog[3]
    if WebLog[5][:13] != "-":
        UserLoginTimestamp = int(WebLog[5][:13])
    else:
        UserLoginTimestamp = "-"
    IP_Type = WebLog[9] 
    Src_Address = WebLog[10]
    Dst_Address = WebLog[11]
    Protocol = WebLog[12]
    Src_Port = WebLog[13]
    Dst_Port = WebLog[14]
    Method = WebLog[15]
    Host = WebLog[16]
    if Host[:4] == "www.":
        Host = Host[4:]
    try: 
        fststring = Host[0]
        secstring = Host[1]
        trdstring = Host[2]
    except:
        continue
    if fststring == '.':
        fststring = "dot"
    if secstring == '.':
        secstring = "dot"
    if trdstring == '.':
        trdstring = "dot"
    is_phishing = 0
    Path = WebLog[17]


    ttime = time.time()
    dtime = datetime.utcfromtimestamp(int(ttime)).strftime('%Y.%m.%d')
    timestamp = datetime.fromtimestamp(int(ttime)).isoformat()
    requesttimestamp = datetime.fromtimestamp(int(ReqTimestamp)).isoformat()
    flowstarttimestamp = datetime.fromtimestamp(int(FlowTimestamp)).isoformat()
    _index = "so-import-"+dtime


    RawLog = {
        "@timestamp": timestamp,
        "requset.timestamp": ReqTimestamp,
        "flowstart.timestamp": FlowTimestamp, 
        "user.name": WebUsername, 
        "session.id": Session_ID, 
        "login.timestamp": UserLoginTimestamp, 
        "ip.type": IP_Type,
        "source.ip": Src_Address,
        "source.port": Src_Port,
        "destination.ip": Dst_Address,
        "destination.port": Dst_Port,
        "network.transport": Protocol,
        "method": Method,
        "domain": Host,
        "path": Path,
        "log.source": "webaccesslog"
        }
    es.index(index=_index, body=RawLog)

    
    try:
        for site in phish_data[0][fststring][secstring][trdstring]:
            if site == Host:
                is_phishing = 1
    except:
        pass

    if is_phishing:
        if IP_Type == ("4" or "6in4"):
            IPv4 = Src_Address
            IPv6 = "-"
        elif IP_Type == ("6" or "4in6"):
            IPv4 = "-"
            IPv6 = Src_Address
        else:
            IPv4 = "-"
            IPv6 = "-"
        Alert = {
            "@timestamp": timestamp,
            "alert.type": "Access To Phishing Site", 
            "user.name": WebUsername, 
            "ip.type": IP_Type,
            "ipv4": IPv4, 
            "ipv6": IPv6,
            "destination.ip": Dst_Address,
            "destination.port": Dst_Port,
            "network.transport": Protocol,
            "method": Method,
            "domain": Host,
            "path": Path,
            "detected.by": "loganalyzer",
            "log.source": "webaccesslog"
            }
        es.index(index=_index, body=Alert)
