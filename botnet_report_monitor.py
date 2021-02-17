"""
This Playbook connects to multiple PAN Firewalls to monitor for behavior-based botnet detections. Any detections found by the PAN Firewall are processed by this Playbook if they have a confidence score higher than the configured value. First each of the detections is checked against an allowlist of known false positives and if the traffic source is not on the allowlist the botnet detection is used to create a ticket in ServiceNow and notify collaborators using Slack.

Author: Irek Romaniuk (minor changes by the Phantom team)
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import json
import requests
import urllib3
import xmltodict

URL = '/api/?type=report&reporttype=predefined&reportname=botnet&key='
API = '<API_Key>'
# Min confidence
CONFIDENCE = 2
# Firewall addresses
PAN = ['<PAN_URL#1>', '<PAN_URL#2>', '<PAN_URL#3>']

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # get the 'Botnet_False_Positive_Allowlist' custom list in order to exclude sources included in it
    include = True
    success, message, botnet_allowlist = phantom.get_list(list_name='Botnet_False_Positive_Allowlist')
    botnet_allowlist = [[str(j) for j in i] for i in botnet_allowlist]
    
    # filter down to only valid ip ranges
    valid_botnet_allowlist = []
    for row in botnet_allowlist:
        botnet_ip = row[0]
        if botnet_ip and phantom.valid_net(botnet_ip):
            valid_botnet_allowlist.append(botnet_ip)
            
    botnet_allowlist = valid_botnet_allowlist
           
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    result = "IP Address/Username/Description:\n" 
    for pan in PAN:
        phantom.debug('Firewall {} called'.format(pan))
        try:
            response = requests.get('https://' + pan + URL + API, verify=False, timeout=3)
        except requests.exceptions.ConnectionError: # as err:     
            data = None       
        doc = json.loads(json.dumps(xmltodict.parse(response.text)))
        try:
            data = doc['report']['result']['entry']
        except KeyError:
            data = None            
        if data:                        
            if type(data) is dict:
                phantom.debug('Confidence: {} {}'.format(data['confidence'], CONFIDENCE))
                if int(data['confidence']) > int(CONFIDENCE):
                    for net in botnet_allowlist:
                        phantom.debug('{} {}'.format(data['src'], net))
                        if phantom.valid_ip(str(data['src'])) and phantom.valid_net(net):
                            if phantom.address_in_network(str(data['src']), net): 
                                break
                            else:                                   
                                if data['srcuser'] != "unknown user":
                                    phantom.debug('{} {} {}'.format(data['src'], data['srcuser'], data['description']))
                                    if str(data['src']) not in result:
                                        result = result + '\n' + '{:15} {:25} {:40}'.format(data['src'], data['srcuser'], data['description'])                    
            else:   
                for entry in data:                    
                    phantom.debug('Confidence: {} {}'.format(entry['confidence'], CONFIDENCE))
                    if int(entry['confidence']) > int(CONFIDENCE):
                        for net in botnet_allowlist:
                            phantom.debug('{} {}'.format(entry['src'], net))
                            if phantom.valid_ip(str(entry['src'])) and phantom.valid_net(net):
                                if phantom.address_in_network(str(entry['src']), net): 
                                    break 
                                else:    
                                    phantom.debug('{} not in {}'.format(str(entry['src']), net))
                                    if entry['srcuser'] != "unknown user":
                                        phantom.debug('{} is known user'.format(entry['srcuser']))                                                 
                                        if str(entry['src']) not in result:
                                            result = result + '\n' + '{:15} {:25} {:40}'.format(entry['src'], entry['srcuser'], entry['description'])    
                        
    phantom.debug('result: {} count: {}\n'.format(result, result.count('\n'))) 
    if result.count('\n') > 1:
        # call 'create_ticket_1' block
        create_ticket_1(container=container, results=result)

    return

"""
Create a ticket in ServiceNow with the context to investigate and mitigate the potential botnet infection.
"""
def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
    # phantom.debug('Results: {}'.format(results))
    # collect data for 'create_ticket_1' call
    pb_info = phantom.get_playbook_info()                
    playbook_name = pb_info[0].get('name', None)

    parameters = []  
    desc_sufix = '''
    
    Action Required:
 
Scan machine(s) with multiple Anti-Virus and Anti-Malware solutions
 
Suggestions:
- Microsoft Security Essentials
- Kaspersky TDSS Rootkit Killer
- Malware Bytes
- Symantec
 
Resolution: 
 
Provide logs of scan results to Security Operations 

Reboot affected host(s) as needed to fully clear quarantines malware
    
    '''
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'short_description': "Issue: Possible botnet activity (" + str(results.count('\n')-1) + ")",
        'description': results + desc_sufix,
        'table': "incident",
        'fields': "{\"urgency\": \"1\", " +
             "\"impact\": \"3\", " +
             "\"comments\": \"Playbook name: %s\", " % playbook_name +
             "\"assignment_group\": \"Help Desk\", " +
             "\"company\": \"Company\", " +
             "\"caller_id\": \"netpro\", " +
             "\"u_affected_business_service\": \"Security\", " +
             "\"u_symptom\": \"Infosec Incident\"}",
        'vault_id': "",
    })

    phantom.act("create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_1", callback=send_message_1)
    
    return

"""
Notify the necessary team members via Slack including the ServiceNow ticket ID.
"""
def send_message_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_message_1() called')
    
    # collect data for 'send_message_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.data.*.number', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_message_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'destination': "phantom",
                'message': "botnet detected: " + results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("send message", parameters=parameters, assets=['slack'], name="send_message_1", parent_action=action)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return