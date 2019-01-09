#!/usr/bin/python
# python3
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
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "zGvtChecker"
  }
#params = {'apikey': os.environ['VT_API_KEY'], 'resource':'[md5hash]'}

for h in sys.argv[1:]:
#    print (re.search(r"[0-9a-f]{32}", h))
    if re.search(r"\b[0-9a-f]{32}\b", h, re.IGNORECASE):  #ensure input is a valid hash value
        print("checking on %s . . . " % h)
        params = {'apikey': os.environ['VT_API_KEY'], 'resource':h}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params=params, headers=headers)
        while response.status_code==204:
#ToDo:  add countdown timer here; 1-minute timeout
            print ("Rate limit.  Pausing a moment.  Please be patient . . . . \r", end='')
            time.sleep(30)
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params=params, headers=headers)
            
#        print (response)
        json_response = response.json()
    #       print("\tsha is %s" % json_response['sha1'])
    #ToDo:
        '''ToDo: test whether any response came back.  A really bad request will engender a simple "[]"; otherwise we should get a json object with, at a minimum:      
            response_code
            resource
            verbose_msg
        '''
        myPpty='response_code'
        myResponse=json_response[myPpty]
#        print ("\t%s is %s" % (myPpty, myResponse) )
        if myResponse==0 :
            print ('no record')
            # we have either submitted a bad request (but this should have been filtered with the test for a valid has at the beginning of the for loop) or there is no record (verbose_msg =~ "The requested resource is not among the finished, queued or pending scans"
        else:
            print ('%d of %d scans identified this as malicious' % (json_response['positives'], json_response['total']))
            if json_response['positives']:
                posHash[h]=json_response['positives']
            else:
                negHash[h]=0
    else:
            print ('>%s< is not a valid MD5 hash' % h)
#ToDo:  print summary:  posHash, negHash
print ('done')

# Access individual elements with: json_response['sha1']

