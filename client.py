#!/usr/bin/python
import sys
import os
import random
import time
import subprocess
import glob
import datetime

def check_input(year, month, day):
    if int(month) > 12 or int(month) < 0 or int(day) < 0 or int(day) > 31:
        print "error: enter valid date"
        sys.exit(1);


if __name__ == "__main__":

    namespace = "/ndn/colostate.edu/netsec"
    
    atmospath = os.getenv("ATMOS_PATH")

    if not atmospath:
        atmospath = os.path.dirname(sys.argv[0])

    client = os.path.join(atmospath, 'client')

    start_date = raw_input("Start Date in YYYY/MM/DD? ")
    #start_date = "1902/01/15"
    year, month, day = start_date.split("/")
#    print year, month, day

    check_input(year, month, day)

    end_date = raw_input("End Date in YYYY/MM/DD? ")
    #end_date = "1902/01/18"
    year_end, month_end, day_end = end_date.split("/")
    #print year_end, month_end, day_end

    check_input(year_end, month_end, day_end)

    month = int(month)
    day = int(day)

    month_end = int(month_end)
    day_end = int(day_end)


    #there is no zero-th month, make index 0 = 0
    months = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if( int(year) % 4 == 0):
        if int(year[2]) + int(year[3]) != 0:
            months[1] = 29;
        elif (int(year) % 400 == 0 ):
            months[1] = 29;

    year = int(year)
    year_end = int(year_end)
    

    command = "rm -f *tmp*"
    f = os.popen(command)

    
    #enumerate rest of the dates
    if(month_end > month):
        for item in range(day, months[month]+1):
            #time.sleep(1)
            filename =  namespace + ("/pr_%d/%02d/%02d/00") %(year, month, item)
            tmp_filename = ("pr_%d_%02d_%02d") %(year, month, item)
            #print "./client " + namespace+filename  + tmp_filename+".tmp.nc"
            x = time.time()
            print "Asking for %s, Saving to %s.tmp.nc" %(filename, tmp_filename)      
            command1 = subprocess.Popen([client, filename, tmp_filename+".tmp.nc"], stdout=subprocess.PIPE)
            out, err = command1.communicate()
            print "Time for %s.tmp.nc %s= " %(tmp_filename, time.time() - x)

        for item in range(1, day_end+1):
            #time.sleep(1)
            filename =  namespace + ("/pr_%d/%02d/%02d/00") %(year, month_end, item)
            tmp_filename = ("pr_%d_%02d_%02d") %(year_end, month_end, item)

            x = time.time()
            print "Asking for %s, Saving to %s.tmp.nc" %(filename, tmp_filename)      
            command1 = subprocess.Popen([client, filename, tmp_filename+".tmp.nc"], stdout=subprocess.PIPE)
            out, err = command1.communicate()
            print "Time for %s.tmp.nc %s= " %(tmp_filename, time.time() - x)
    else:

        for item in range(day, day_end+1):
            #time.sleep(1)
            filename =  namespace + ("/pr_%d/%02d/%02d/00") %(year, month, item)
            tmp_filename = ("pr_%d_%02d_%02d") %(year, month, item)
            

            x = time.time()
            print "Asking for %s, Saving to %s.tmp.nc" %(filename, tmp_filename)      
            command1 = subprocess.Popen([client, filename, tmp_filename+".tmp.nc"], stdout=subprocess.PIPE)
            out, err = command1.communicate()
            print "Time for %s.tmp.nc %s= " %(tmp_filename, time.time() - x)

    

    x = time.time()
    join_list = []
    join_str = ''
    path = '.'
    for infile in glob.glob('*.tmp.nc'):
        y, m, d = infile.split(".tmp.nc")[0].split('pr_')[1].split('_')
        date2 = datetime.date(int(y), int(m), int(d))
        date1 = datetime.date(1901, 01, 01)
        diff = date2 - date1
        #print diff.days
        command1 = subprocess.Popen(["ncdump", "-v", "time",  infile], stdout=subprocess.PIPE)
        out, err = command1.communicate()
        if str(diff.days) in out:
            join_list.append(infile)
        else:
            print "corrupted file %s...skipping" %(infile)
            pass

    print "Joining files.."
    for item in sorted(join_list):
        join_str = join_str + ' '  + item
        #print join_str
    #print 'join_str = ', join_str
    
    if len(join_list) == 1:
        f = os.popen("cp %s pr_%s_%s_%s_%s_%s_%s.nc" %(join_str, year, month, day, year_end, month_end, day_end))
    else:
        f = os.popen("ncrcat -O %s pr_%s_%s_%s_%s_%s_%s.nc" %(join_str, year, month, day, year_end, month_end, day_end))
    print "Concat + write time",  time.time() - x
    print "Wrote to pr_%s_%s_%s_%s_%s_%s.nc" %(year, month, day, year_end, month_end, day_end)

    sys.exit(0);
    

