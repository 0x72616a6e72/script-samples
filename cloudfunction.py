import json
import requests

# export log data from Proofpoint and import it into Sumologic
# intended to be run as  Google Cloud Function
# uses the secrets store for API keys etc

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

# Our preferred Proofpoint 
api_url = api_url_base + api_all 
    
# Certificate Authority
cafile = 'cacert.pem' # http://curl.haxx.se/ca/cacert.pem

###############################################################################################################################
def transfer_log_data():
    # This is the Main function. 

    # We're using GCP's Secret Manager to store API keys and other sensitive info
    #  Proofpoint TAP SIEM API credentials
    api_service_principal = access_secret_version("admin", "ProofpointAPIServicePrincipal", "latest")
    api_secret = access_secret_version("admin", "ProofpointAPIsecret", "latest")

    # Sumo API URL
    sumo_endpoint = access_secret_version("admin", "SumologicHTTPSendpoint", "latest")

    jsonTAPLogData = get_TAP_logs(api_url, api_service_principal, api_secret)

    if jsonTAPLogData.status = 200
        status = post_to_Sumologic(sumo_endpoint, jsonTAPLogData)
    else status = "Unable to retrieve log data from Proofpoint: " + api_url + ", status code=" + jsonLogData.status

    return status

###############################################################################################################################
def get_TAP_logs(urlTAPsiemAPI, strService_principal, strSecret):
    """
    Pull data from the Proofpoint TAP SIEM API
    Parameters: 
        url of Proofpoint TAP SIEM API
        API Service Principal
        API Secret
    """ 

    # Criteria for selecting records - these will be URL parameters
    payload = {'format': 'JSON', 'sinceSeconds': '3600', 'threatStatus': ['active', 'cleared', 'falsePositive']}

    # What format of data are we requesting?
    headers = {'Accept': 'application/json'}

    # Now get the data
    jsonTAPLogData = requests.get(urlTAPsiemAPI, headers=headers, 
        params=payload,
        auth=requests.auth.HTTPBasicAuth(strService_principal, strSecret),
        verify=cafile)

    return jsonTAPLogData

###############################################################################################################################
def post_to_Sumologic(urlSumoEndpoint, jsonLogData):
    """
    Post json records to Sumologic's URL API endpoint
    Parameters:
        url for Sumo's API endpoint
        json blob of log data
    """
    sentData = requests.post(sumo_endpoint, json=jsonLogData, headers={"content-type": "application/json"})

    return sentData.status + " data posted to Sumologic"

###############################################################################################################################
def access_secret_version(project_id, secret_id, version_id):
    """
    https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets?hl=en_US#secretmanager-create-secret-python
    Access the payload for the given secret version if one exists. The version
    can be a version number as a string (e.g. "5") or an alias (e.g. "latest").
    """

    # Import the Secret Manager client library.
    from google.cloud import secretmanager_v1beta1 as secretmanager

    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version.
    name = client.secret_version_path(project_id, secret_id, version_id)

    # Access the secret version.
    response = client.access_secret_version(name)

    secret = response.payload.data.decode('UTF-8')
    return secret

