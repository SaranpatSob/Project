import os,shutil

filepath = '/home/admin/cron/testfile/'
archrive = '/home/admin/cron/testfile_archrive/'
entries = os.listdir(filepath)
for entry in entries:
    print(entry)
    f2 = open(filepath+entry, "r")
    while True:
        CaptiveLog = f2.readline()
        if not CaptiveLog:
            break
        print(CaptiveLog)
    shutil.move(filepath+entry, archrive)