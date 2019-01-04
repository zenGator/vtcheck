#!/usr/bin/python
# python3
# VT_API_KEY set in .bashrc:  export VT_API_KEY='blahblahblah'
# 
import os
# show with: os.environ['VT_API_KEY']
import requests
import json
import sys

#print ("This is the name of the script: ", sys.argv[0])
print ("Processing %d hashes." % (len(sys.argv)-1))
#print ("The arguments are: " , str(sys.argv))

#see https://www.tutorialspoint.com/python/python_command_line_arguments.htm


headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "zGvtChecker"
  }
params = {'apikey': os.environ['VT_API_KEY'], 'resource':'[md5hash]'}

for h in sys.argv[1:]:
#ToDo:
    '''ToDo:  test that each "hash" is in fact [0-9a-z]{32} 
    '''
    print("checking on %s . . . " % h)
    params = {'apikey': os.environ['VT_API_KEY'], 'resource':h}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params=params, headers=headers)
    json_response = response.json()
#       print (json_response)
#       print("\tsha is %s" % json_response['sha1'])
#ToDo:
    '''ToDo: test whether any response came back.  A really bad request will engender a simple "[]"; otherwise we should get a json object with, at a minimum:      
        response_code
        resource
        verbose_msg
    '''
    myPpty='response_code'
    myResponse=json_response[myPpty]
    print ("\t%s is %s" % (myPpty, myResponse) )
    if myResponse==0 :
        print ('no record')
        # we have either submitted a bad request (but this should have been filtered with the test for a valid has at the beginning of the for loop) or there is no record (verbose_msg =~ "The requested resource is not among the finished, queued or pending scans"
    else:
         print ('found')   
       
print ('done')

# Access individual elements with: json_response['sha1']

