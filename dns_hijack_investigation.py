"""
This Playbook is part of the Splunk Analytic Story called DNS hijack. It is made to be run when the Detection Search within that story called "DNS record changed" is used to identify DNS record changes for cloud and corporate domains. The detection search is dependent on a support searched called "Discover DNS records" which finds the common DNS responses for the last 30 days of monitored corporate domains and cloud providers (located in lookups: cim_corporate_email_domains.csv, cim_corporate_web_domains.csv, and cloud_domains.csv from Splunk CIM App). Stores these responses under lookup discovered_dns_records.csv. The playbook takes in the DNS record changed and uses geoip, whois, censys and passive total to detect if DNS issuers changed.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

def extract_domain_from_url(url):
    try:
        domain = url.split('://', 1)[1].split('/', 1)[0]
    except:
        return None
    return domain

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    return

"""
Condition 1:  Investigate artifacts where sourceAddress is not empty
Condition 2: Investigate artifacts where destinationAddress is not empty
Condition 3: Investigate artifacts where dst is not empty
Condition 4: Investigate artifacts where src is not empty
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.current_answer", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Geolocate_IP(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Condition 1:  Investigate artifacts where destinationDnsDomain is not empty
Condition 2: Investigate artifacts where requestURL is not empty
Condition 3: Investigate artifacts where sourceDnsDomain is not empty
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.query", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Malware_Domain_Lookup(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Passive_Total_Domain_Reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
WHOIS lookup on the IP address
"""
def WHOIS_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('WHOIS_Lookup() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'WHOIS_Lookup' call
    results_data_1 = phantom.collect2(container=container, datapath=['Geolocate_IP:action_result.parameter.ip', 'Geolocate_IP:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'WHOIS_Lookup' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("whois ip", parameters=parameters, assets=['whois'], callback=WHOIS_Lookup_callback, name="WHOIS_Lookup", parent_action=action)

    return

def WHOIS_Lookup_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('WHOIS_Lookup_callback() called')
    
    Censys_IO_IP_Lookup(action=action, success=success, container=container, results=results, handle=handle)
    PassiveTotal_IP_Reputation(action=action, success=success, container=container, results=results, handle=handle)

    return

def Add_Data_To_Container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_Data_To_Container() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Results')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def Format_Results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_Results() called')
    
    template = """IP Address Information
GeoIP Information {0}
Whois Information {1}
IP Classification {5}
Is IP Sinkholed {6}
SSL Certificate From IP Details
Issuer Common Name {2}
Issuer Country {3}
Issuer Org {4}

Domain Information
Is domain a known malware domain list: {7}
Passive Total Domain Reputation: {8}"""

    # parameter list for template variable replacement
    parameters = [
        "Geolocate_IP:action_result.message",
        "WHOIS_Lookup:action_result.message",
        "Censys_IO_IP_Lookup:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.common_name",
        "Censys_IO_IP_Lookup:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.country",
        "Censys_IO_IP_Lookup:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.organization",
        "PassiveTotal_IP_Reputation:action_result.summary.classification",
        "PassiveTotal_IP_Reputation:action_result.data.*.sinkhole",
        "Malware_Domain_Lookup:action_result.summary.malicious",
        "Passive_Total_Domain_Reputation:action_result.data.*.classification.classification",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Results")

    Add_Data_To_Container(container=container)

    return

def join_Format_Results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Format_Results() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'Censys_IO_Certificate_Lookup', 'PassiveTotal_IP_Reputation', 'Malware_Domain_Lookup', 'Passive_Total_Domain_Reputation' ]):
        
        # call connected block "Format_Results"
        Format_Results(container=container, handle=handle)
    
    return

"""
Geolocate the IP address using Maxmind
"""
def Geolocate_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Geolocate_IP() called')

    # collect data for 'Geolocate_IP' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.current_answer', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Geolocate_IP' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=WHOIS_Lookup, name="Geolocate_IP")

    return

def Passive_Total_Domain_Reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Passive_Total_Domain_Reputation() called')

    # collect data for 'Passive_Total_Domain_Reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.query', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Passive_Total_Domain_Reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'to': "",
                'domain': container_item[0],
                'from': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, app={ "name": 'PassiveTotal' }, callback=join_Format_Results, name="Passive_Total_Domain_Reputation")

    return

def Malware_Domain_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Malware_Domain_Lookup() called')

    # collect data for 'Malware_Domain_Lookup' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.query', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Malware_Domain_Lookup' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                'include_inactive': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, app={ "name": 'Malware Domain List' }, callback=join_Format_Results, name="Malware_Domain_Lookup")

    return

def Censys_IO_IP_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Censys_IO_IP_Lookup() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Censys_IO_IP_Lookup' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.current_answer', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Censys_IO_IP_Lookup' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("lookup ip", parameters=parameters, assets=['censys'], callback=Check_if_data_found_for_Censys_query, name="Censys_IO_IP_Lookup", parent_action=action)

    return

def Censys_IO_Certificate_Lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Censys_IO_Certificate_Lookup() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Censys_IO_Certificate_Lookup' call
    results_data_1 = phantom.collect2(container=container, datapath=['Censys_IO_IP_Lookup:action_result.data.*.ports.443.https.tls.certificate.parsed.fingerprint_sha256', 'Censys_IO_IP_Lookup:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Censys_IO_Certificate_Lookup' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'sha256': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("lookup certificate", parameters=parameters, app={ "name": 'Censys' }, callback=join_Format_Results, name="Censys_IO_Certificate_Lookup", parent_action=action)

    return

def PassiveTotal_IP_Reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('PassiveTotal_IP_Reputation() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'PassiveTotal_IP_Reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.current_answer', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'PassiveTotal_IP_Reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'from': "",
                'to': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, app={ "name": 'PassiveTotal' }, callback=join_Format_Results, name="PassiveTotal_IP_Reputation", parent_action=action)

    return

def Check_if_data_found_for_Censys_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Check_if_data_found_for_Censys_query() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Censys_IO_IP_Lookup:action_result.data.*.ports.443.https.tls.certificate.parsed.fingerprint_sha256", "!=", ""],
        ],
        name="Check_if_data_found_for_Censys_query:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Censys_IO_Certificate_Lookup(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return