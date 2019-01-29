#!/usr/bin/python
# python3
# https://github.com/zenGator/vtcheck/edit/master/vtchecker.py
# VT_API_KEY set in .bashrc:  export VT_API_KEY='blahblahblah'
# 
import os
# show with: os.environ['VT_API_KEY']
import requests
import json
import sys
import re
import time

#print ("This is the name of the script: ", sys.argv[0])
print ("Processing %d hashes." % (len(sys.argv)-1))
#print ("The arguments are: " , str(sys.argv))

#see https://www.tutorialspoint.com/python/python_command_line_arguments.htm

posHash={}
negHash={}
posObjects={}
negObjects={}
unkObjects=[]
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "zGvtChecker"
  }
VT_REPORT_URL='https://www.virustotal.com/vtapi/v2/file/report'
c=0     #count the number of checks we make; after number 4, we wait a bit
#params = {'apikey': os.environ['VT_API_KEY'], 'resource':'[md5hash]'}

for h in sys.argv[1:]:
    c+=1
    if re.search(r"\b[0-9a-f]{32}\b", h, re.IGNORECASE):  #ensure input is a valid hash value
        print("checking on %s . . . " % h)
        params = {'apikey': os.environ['VT_API_KEY'], 'resource':h}
        response = requests.get(VT_REPORT_URL,  params=params, headers=headers)
        if c==5:
            print ("Rate limit.  Pausing a bit.  Please be patient . . . . \r", end='')
            time.sleep(45)
        if c > 5:
            print ("Waiting for 16 seconds between each response.  Please be patient . . . . \r", end='')
            time.sleep(16)
            response = requests.get(VT_REPORT_URL,  params=params, headers=headers)
        while response.status_code==204:
#ToDo:  add countdown timer here; 1-minute timeout
            print ('%s\r' % (" " * 80), end='')
            print ("Rate limit.  Pausing a bit longer.  Please be patient . . . . ")
            time.sleep(10)
            response = requests.get(VT_REPORT_URL,  params=params, headers=headers)
            
        if response.status_code==404:
                        print ('%s\r' % (" " * 80), end='')
                        print ('major error:  404 returned')
                        quit()
        json_response = response.json()
    #       print("\tsha is %s" % json_response['sha1'])
    #       now, we can see a particular scan:
    #           json_response['scans']['Fortinet']

        myPpty='response_code'
        myResponse=json_response[myPpty]
        print ('%s\r' % (" " * 80), end='')
#        print ("\t%s is %s" % (myPpty, myResponse) )
        if myResponse==0 :
            print ('No record')
            # we have either submitted a bad request (but this should have been filtered with the test for a valid has at the beginning of the for loop) or there is no record (verbose_msg =~ "The requested resource is not among the finished, queued or pending scans"
            unkObjects.append(h)
        else:
            print ('%d of %d scans identified this as malicious' % (json_response['positives'], json_response['total']))
            if json_response['positives']:
                posHash[h]=json_response['positives']
                posObjects[h]=json_response
            else:
                negHash[h]=0
                negObjects[h]=json_response
    else:
            print ('>%s< is not a valid MD5 hash' % h)
# Access individual elements with: json_response['sha1']
# or in below loops:  posObjects[obj]['sha256'])
print ('Lookups complete.  Summary:')
print ('Items found to be malicious: %d' % len(posObjects))
for obj in posObjects:
    print ('\t%s (%d/%d)' % (obj, posObjects[obj]['positives'], posObjects[obj]['total']))
print ('\nItems found to be benign: %d' % len(negObjects))
for obj in negObjects:
    print ('\t%s' % obj)
print ('\nNo records found for %d items' % len(unkObjects))
for obj in unkObjects:
    print ('\t%s' % obj)

