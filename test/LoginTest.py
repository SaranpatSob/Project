#--------------------------------------------HEADER--------------------------------------------------------------#
#ใน login log จะเก็บ 2 ครั้งคือครั้ง login จะมี login timestamp ใน field ของ logout timestamp จะไม่มี(-)
#ในครั้งที่ 2 จะเกิด Timer Timeout โดยการเก็บ log ครั้งที่ 2 นั้น จะบันทุก Login timestamp เดียวกับครั้งรก และครั้งนี้จะบันทึก logout timestamp ด้วย
#timestamp ใน login log และ captive log ไม่เท่ากัน 3 ตัวท้ายเป็น millisec (Unix timestamp)
# LoginLog Field = [RunNo., Login Timestamp, Username@role.ku.ac.th, Logout Timestamp, MAC Address, IPv4, IPv6, agent ip, status,conclusion]
# CaptiveLog Field = [logintimestamp, web ที่ทำการ login, username, IPv4, IPv6, status, conclusion] 

# ใน CaptiveLog >> access = เข้าหน้า login page, success = login สำเร็จ, fail = login fail
# ใน Login Log >> Login-page = login สำเร็จ, Timeout Timer = หมดเวลาเชื่อมต่อ, Relogin = เมื่อมี เกิด timeout timer แล้วเรา login อีครั้ง (sesstion ยังอยู่), Force-Logout = user เป็นคนกด logout เอง ,autologin = wpa ไม่ผ่านหน้า page(บางคน)
#-------------------------------------------------------------------------------------------------------------------

import fileinput,sys
#argv argument แล้วค่อยเอามาใส่ในไฟล์


f1 = fileinput.input(files=sys.argv[1])
f2 = fileinput.input(files=sys.argv[2])
# f2 = fileinput.FileInput(openhook=fileinput.hook_encoded("utf-8", "surrogateescape"))


Login_FailList = []
Login_Fail = {}
LoginAction = {}
Multiple_LoginList = {}
Multiple_Login = {}
TimePeriod = 60
TimeStamp = 0
FirstTimestamp = 0
TimeFirstLine = 1


while True:
    CaptiveLog = f2.readline()
    if not CaptiveLog:
        break
    CaptiveLog = CaptiveLog.split(' ')
    if TimeFirstLine:
        TimeStamp = int(CaptiveLog[0][:10])+TimePeriod
        LoginAction[TimeStamp] = {"access":0,"success":0,"fail":0,"login-page":0,"TIMEOUT":0,"RE-LOGIN":0,"force-logout":0,"autologin":0,"sso-page":0,"logout-all-page":0,"LoginIP":[]}
        TimeFirstLine = 0
        FirstTimestamp = TimeStamp
    CaptiveTimestamp = CaptiveLog[0][:10]
    CaptiveStatus = CaptiveLog[5]
    CaptiveUser = CaptiveLog[2].lower()
    if CaptiveStatus == "access":
        if int(CaptiveTimestamp) <= TimeStamp:
            LoginAction[TimeStamp]["access"]+=1
        else:
            TimeStamp = TimeStamp+TimePeriod
            LoginAction[TimeStamp] = {"access":1,"success":0,"fail":0,"login-page":0,"TIMEOUT":0,"RE-LOGIN":0,"force-logout":0,"autologin":0,"sso-page":0,"logout-all-page":0,"LoginIP":[]}
        pass
    if not CaptiveUser in Login_Fail.keys():
        Login_Fail[CaptiveUser] = {"S":0,"F":0,"FStreak":0,"MaxStreak":0,"FailTimestamp":[]}
    if CaptiveStatus == "success":
        Login_Fail[CaptiveUser]['S'] +=1
        Login_Fail[CaptiveUser]['FStreak'] = 0
        if int(CaptiveTimestamp) <= TimeStamp:
            LoginAction[TimeStamp]["success"]+=1
        else:
            TimeStamp = TimeStamp+TimePeriod
            LoginAction[TimeStamp] = {"access":0,"success":1,"fail":0,"login-page":0,"TIMEOUT":0,"RE-LOGIN":0,"force-logout":0,"autologin":0,"sso-page":0,"logout-all-page":0,"LoginIP":[]}
    elif CaptiveStatus == "fail":
        Login_Fail[CaptiveUser]['FailTimestamp'].append(CaptiveTimestamp)
        Login_Fail[CaptiveUser]['F'] +=1
        Login_Fail[CaptiveUser]['FStreak'] += 1
        if Login_Fail[CaptiveUser]['FStreak'] > Login_Fail[CaptiveUser]['MaxStreak']:
            Login_Fail[CaptiveUser]['MaxStreak'] = Login_Fail[CaptiveUser]['FStreak']
        if ((Login_Fail[CaptiveUser]['FStreak'] > 5) and (not CaptiveUser in Login_FailList)):
            Login_FailList.append(CaptiveUser)
        if int(CaptiveTimestamp) <= TimeStamp:
            LoginAction[TimeStamp]["fail"]+=1
        else:
            TimeStamp = TimeStamp+TimePeriod
            LoginAction[TimeStamp] = {"access":0,"success":0,"fail":1,"login-page":0,"TIMEOUT":0,"RE-LOGIN":0,"force-logout":0,"autologin":0,"sso-page":0,"logout-all-page":0,"LoginIP":[]}


TimeFirstLine = 1


while True:
    LoginLog = f1.readline()
    if not LoginLog:
        break
    LoginLog = LoginLog.split(' ')
    LoginUser = LoginLog[2].split('@')
    LoginUsername = LoginUser[0].lower()
    LoginStatus = LoginLog[8]
    if TimeFirstLine:
        TimeStamp = FirstTimestamp
        TimeFirstLine = 0
    if (LoginStatus == "TIMEOUT") or (LoginStatus == "force-logout") or (LoginStatus == "logout-all-page"):
        LoginTimestamp = LoginLog[3][:10]
    elif (LoginStatus == "login-page") or (LoginStatus == "autologin") or (LoginStatus == "RE_LOGIN") or (LoginStatus == "sso-page"):
        LoginTimestamp = LoginLog[1][:10]
    if int(LoginTimestamp) > TimeStamp:
        TimeStamp = TimeStamp+TimePeriod
    if (LoginStatus == "login-page") or (LoginStatus == "sso-page"):
        LoginAction[TimeStamp]["LoginIP"].append([LoginLog[5],LoginLog[6]])
        LoginAction[TimeStamp][LoginStatus] += 1
    else:
        LoginAction[TimeStamp][LoginStatus] += 1
    
    
    IPaddress = LoginLog[5].split(".")
    if not LoginUsername in Multiple_Login.keys():
        if LoginLog[5] != "-":
            Multiple_Login[LoginUsername] = {"NowLogin":[],"Area":0}
            if (IPaddress[0] == "158"):
                Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[2])/64) + 1
                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
            elif (IPaddress[0] == "10"):
                Multiple_Login[LoginUsername]["Area"] = int(int(IPaddress[1])/64) + 1
                Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
            else:
                print("Error")
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
                        print("Error")
            else:
                if LoginLog[5] != "-":
                    if (IPaddress[0] == "158"):
                        if (int(int(IPaddress[2])/64) + 1 == Multiple_Login[LoginUsername]["Area"]):
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                        else:
                            if not LoginUsername in Multiple_LoginList.keys():
                                Multiple_LoginList[LoginUsername] = []
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                            event = {LoginTimestamp:{"IPaddress":Multiple_Login[LoginUsername]["NowLogin"],"Area":[Multiple_Login[LoginUsername]["Area"],int(int(IPaddress[2])/64) + 1]}}
                            Multiple_LoginList[LoginUsername].append(event)
                            Multiple_Login[LoginUsername]["NowLogin"] = []
                            Multiple_Login[LoginUsername]["Area"] = 0
                    elif (IPaddress[0] == "10"):
                        if (int(int(IPaddress[1])/64) + 1 == Multiple_Login[LoginUsername]["Area"]):
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                        else:
                            if not LoginUsername in Multiple_LoginList.key():
                                Multiple_LoginList[LoginUsername] = []
                            Multiple_Login[LoginUsername]["NowLogin"].append(LoginLog[5])
                            event = {LoginTimestamp:{"IPaddress":Multiple_Login[LoginUsername]["NowLogin"],"Area":[Multiple_Login[LoginUsername]["Area"],int(int(IPaddress[2])/64) + 1]}}
                            Multiple_LoginList[LoginUsername].append(event)
                            Multiple_Login[LoginUsername]["NowLogin"] = []
                            Multiple_Login[LoginUsername]["Area"] = 0



    # if int(LoginTimestamp) <= TimeStamp:
    #     LoginAction[TimeStamp][LoginStatus] += 1
        
    # else:
    #     TimeStamp = TimeStamp+TimePeriod
    #     if (LoginStatus == "login-page") or (LoginStatus == "sso-page"):
    #         LoginAction[TimeStamp]["LoginIP"].append([LoginLog[5],LoginLog[6]])
    #     LoginAction[TimeStamp][LoginStatus] += 1

print(LoginAction)
print(Login_Fail)
print(Multiple_Login)
print(Multiple_LoginList)


# Login_FailList = []
# Login_Status = {}
# Login_Time = {}
# Login_ReLogin = {}
# Login_Fail = {}
# Login_AST = {}
        

# while True:
#     LoginLog = f1.readline()
#     if not LoginLog:
#         break
#     LoginLog = LoginLog.split(' ')
#     if LoginLog[8] == "TIMEOUT":
#         pass
#     else:
#         if LoginLog[8] == "login-page":
#             user = LoginLog[2].split('@')
#             LoginTimeStamp = LoginLog[1][:10]
#             while True:
#                 CaptiveLog = f2.readline()
#                 if not CaptiveLog:
#                     break
#                 CaptiveLog = CaptiveLog.split(' ')
#                 if CaptiveLog[5] == "access":
#                     pass
#                 CaptiveTimestamp = CaptiveLog[0][:10]
#                 if LoginTimeStamp == CaptiveTimestamp:
#                     if user[0].lower() == CaptiveLog[2].lower():
#                         status = CaptiveLog[5]
#                         break
#             username = user[0].lower()
#             if not username in Login_Status.keys():
#                 Login_Status[username] = {"S":0,"F":0,"FStreak":0,"MaxStreak":0}
#             if status == "success":
#                 Login_Status[username]['S'] +=1
#                 Login_Status[username]['FStreak'] = 0
#             elif status == "fail":
#                 Login_Status[username]['F'] +=1
#                 Login_Status[username]['FStreak'] += 1
#                 if Login_Status[username]['FStreak'] > Login_Status[username]['MaxStreak']:
#                     Login_Status[username]['MaxStreak'] = Login_Status[username]['FStreak']
#                 if ((Login_Status[username]['FStreak'] > 5) and (not username in Login_FailList)):
#                     Login_FailList.append(username)
# print(Login_Status)
    
