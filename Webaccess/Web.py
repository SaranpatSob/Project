#--------------------------------------------HEADER--------------------------------------------------------------#
# Web Log = [Request Timestamp (?), (?), Receive Timestamp (?), (?), Username, Time(?), (?), (?), (?), 4,6(?), Source IP(v4,v6), Destination IP(v4,v6), Protocol (TCP,UDP), Source Port, Destination Port, Method, Domain, Path, Domain(Post), Agent]
#-----------------------------------------------------------------------------------------------------------------#


import fileinput,sys

f1 = fileinput.input(files=sys.argv[1])

WebAccess = {}
PostFirst = {}
TimePeriod = 60
TimeStamp = 0
FirstTimestamp = 0
TimeFirstLine = 1


while True:
    WebLog = f1.readline()
    if not WebLog:
        break
    WebLog = WebLog.split(' ')
    if (WebLog[4] != '-'):
        User = WebLog[4].lower()
    else:
        User = '-'
    SrcAdd = WebLog[10]
    DstAdd = WebLog[11]
    Protocol = WebLog[12]
    SrcPort = WebLog[13]
    DstPort = WebLog[14]
    Method = WebLog[15]
    Domain = WebLog[16]


    if TimeFirstLine:
        TimeStamp = int(WebLog[0][:10])+TimePeriod
        WebAccess[TimeStamp] = {"Website":{},"Source":[],"Destination":[],"Method":{"GET":0, "POST":0, "HTTPS":0, "HTTP":0,"HEAD":0}, "Protocol":{"TCP":0,"UDP":0}}
        TimeFirstLine = 0
        # FirstTimestamp = TimeStamp
    WebTimestamp = int(WebLog[0][:10])
    if WebTimestamp > TimeStamp:
        WebAccess[TimeStamp] = {"Website":{},"Source":[],"Destination":[],"Method":{"GET":0, "POST":0, "HTTPS":0, "HTTP":0,"HEAD":0}, "Protocol":{"POST":0,"GET":0},}
        TimeStamp = TimeStamp+TimePeriod    
    WebAccess[TimeStamp]["Source"].append([SrcAdd,SrcPort])
    WebAccess[TimeStamp]["Destination"].append([DstAdd,DstPort])
    WebAccess[TimeStamp]["Method"][Method]+=1
    WebAccess[TimeStamp]["Protocol"][Protocol]+=1
    if not Domain in WebAccess[TimeStamp]["Website"].keys():
        WebAccess[TimeStamp]["Website"][Domain] = {"AccessCount":0,"Method":{"GET":0, "POST":0, "HTTPS":0, "HTTP":0, "HEAD":0}, "Protocol":{"TCP":0,"UDP":0}}
        if Method == "POST":
            if not Domain in PostFirst.keys():
                PostFirst[Domain]={}
            if not User in PostFirst[Domain].keys():
                PostFirst[Domain][User]=WebTimestamp
    WebAccess[TimeStamp]["Website"][Domain]["AccessCount"]+=1
    WebAccess[TimeStamp]["Website"][Domain]["Protocol"][Protocol]+=1    
    WebAccess[TimeStamp]["Website"][Domain]["Method"][Method]+=1

# print(WebAccess)
# print(PostFirst)