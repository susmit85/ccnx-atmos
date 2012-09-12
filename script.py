#!/usr/bin/python
import os, sys
import datetime
import time
import socket

ip_addr = socket.gethostbyname(socket.gethostname())

# ccnget /pr_1901/01/29
#/GCRM/ZGrd/r6/pr/

namespace = "/GCRM/ZGrd/r6/pr"
#namespace = "/ndn/colostate.edu/netsec/"
filename = sys.argv[1]

argument = sys.argv[2]

#file exsits
#try:
#    fp = open ("vizualize_"+ip_addr) 
#    last_modified = time.ctime(os.path.getmtime("vizualize_"+ip_addr))
#    last_time = time.strptime(last_modified)
#    last_time = datetime.datetime.fromtimestamp(time.mktime(last_time))
#    now = datetime.datetime.now()
#    dt = now - last_time
#    delta = dt.days*86400+ dt.seconds
#    if delta > 90:
#        open("vizualize_" + ip_addr , "wb")
#    else:
#        fp = open("vizualize_" + ip_addr , "ab")
#
#except IOError as e:
#    fp = open("vizualize_" + ip_addr , "ab")

    


#fp.write(argument+'\n')
#command = "ccnrm " + argument
#f = os.popen(command)

#print "argument", argument
#differnce from epoch
#year, month, day = argument.split(namespace)[1].split("/")
year, month, day = argument.split('_')[1].split('/')

#print year, month, day
#filename = "pr_19020101_060000.nc"



date1 = datetime.date(1901, 01, 01)
date2 = datetime.date(int(year), int(month), int(day))

#print "date1: ", date1
#print "date2: ", date2
diff = date2 - date1
start = diff.days 
end = start + 1


#start, end = sys.argv[1].split(',')
#print start, end
#filename =  sys.argv[2]

#namespace = sys.argv[3]
#tmp_namespace = sys.argv[4]

#command = "ccnrm " + namespace + filename + ".tmp ";
#command = "ccnrm " + tmp_namespace + filename + ".tmp ";#
#print command
#f = os.popen(command)
command = "ncdump -v time " + filename +  " |tr '\\n;}' ' '|awk -F 'data:' '{print $2}'|awk -F 'time = ' '{print $2}'|sed 's/ //g'"
#print command

val_list = []
f = os.popen(command)
for i in f.readlines():
    val_list = i.strip().split(',');
#    val_list.append(float(i.strip()))

#print val_list


for position, item in enumerate(val_list):
    if float(item) >= float(start):
#       print item, position
        start_index = position
        break


#default value
end_index = len(val_list) -1

for position, item in enumerate(val_list):
    if float(item) >= float(end):
        end_index = position - 1
        break

#print start_index, end_index

command = "ncks -O -d time," + str(start_index) + "," + str(end_index) + " " + filename + " " + filename + ".tmp"
#print command
f = os.popen(command)
print filename+".tmp",
