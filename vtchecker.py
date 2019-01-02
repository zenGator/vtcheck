# python3
# VT_API_KEY set in .bashrc:  export VT_API_KEY='blahblahblah'
# 
import os
# show with: os.environ['VT_API_KEY']
import requests
import json
import sys

print "This is the name of the script: ", sys.argv[0]
print "Number of arguments: ", len(sys.argv)
print "The arguments are: " , str(sys.argv)

#see https://www.tutorialspoint.com/python/python_command_line_arguments.htm


headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "zGvtChecker"
  }
params = {'apikey': os.environ['VT_API_KEY'], 'resource':'[md5hash]'}
response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params=params, headers=headers)
json_response = response.json()
#show with:  json_response

# Access individual elements with: json_response['sha1']

