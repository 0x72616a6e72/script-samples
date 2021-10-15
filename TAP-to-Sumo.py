#! /usr/bin/python3
import json
import requests
import base64
import sys

# cron script to pull Proofpoint TAP logs into Sumologic

#*****************************************************
# CHANGE THESE
# api service principal and secret for Proofpoint TAP SIEM API
api_service_principal = '<SECRET>'
api_secret = '<SECRET>'
# Sumologic https Source
sumo_endpoint = 'https://endpoint5.collection.us2.sumologic.com/receiver/v1/http/<SECRET>'
#*****************************************************

# https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
# All SIEM TAP APIs are based on this URL
api_url_base = 'https://tap-api-v2.proofpoint.com'

# Available endpoints
api_clicks_blocked = '/v2/siem/clicks/blocked'
api_clicks_permitted = '/v2/siem/clicks/permitted'
api_messages_blocked = '/v2/siem/messages/blocked'
api_messages_delivered = '/v2/siem/messages/delivered'
api_issues = '/v2/siem/issues'
api_all = '/v2/siem/all'

# Certificate Authority
cafile = 'cacert.pem' # http://curl.haxx.se/ca/cacert.pem
# cafile = 'zscaler.pem'

# Construct the API request URL
api_url = api_url_base + api_all 

# Criteria for selecting records - these will be URL parameters
payload = {'format': 'JSON', 'sinceSeconds': '3600', 'threatStatus': ['active', 'cleared', 'falsePositive']}

# What format of data are we requesting?
headers = {'Accept': 'application/json'}

response = requests.get(api_url, headers=headers, 
		params=payload,
    	auth=requests.auth.HTTPBasicAuth(api_service_principal, api_secret),
    	verify=cafile)

print ('URL is ' + response.url)

if response.status_code is 200:
    print("Here's your info: ")
    # print (response.headers['content-type'])
    # print (response.encoding)
    print (response.json())
    # Now post it to Sumo
    sentData = requests.post(sumo_endpoint, data=response.json(), headers={"content-type": "application/json"})
    print ("{} {}".format("[!] POST response code: ", sentData.status_code))  
    # save TAP events to a file for debugging, posterity etc
    with open('output.json', 'a', encoding='utf-8') as outfile: 
        json.dump(response.json(), outfile, ensure_ascii=False, indent=4) 
else:
    print ("{} {}".format("[!] Request Failed with code: ", response.status_code))  
    print (response.text)

sys.exit(0)



