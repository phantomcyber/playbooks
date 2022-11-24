"""
Starting with a single IP address, this playbook gathers a list of related IP addresses, domain names, file hashes, and vulnerability CVE's from Recorded Future. Then Splunk is used to build threat hunting lookup tables and search across multiple data sources for events containing the related entities. Finally, IP addresses are blocked if approved by an analyst and an email is sent to notify a responder if more than 10 of a certain kind of entity are matched at once.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    return

"""
Proceed if the risk score is higher than a certain threshold
"""
def risk_score_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('risk_score_threshold() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.risk.score", ">=", 90],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ip_intelligence_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Build a Splunk query to turn a list of related entities from Recorded Future into a lookup table that can be used for threat hunting across any sourcetype or data model
"""
def format_related_ip_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_related_ip_lookup() called')
    
    template = """| makeresults | eval IP=\"{0}\" | makemv IP delim=\", \" | mvexpand IP | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntip.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_3:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_3:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_related_ip_lookup")

    build_ip_lookup(container=container)

    return

"""
Run the Splunk query that creates the lookup file
"""
def build_ip_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_ip_lookup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'build_ip_lookup' call
    formatted_data_1 = phantom.get_format_data(name='format_related_ip_lookup')

    parameters = []
    
    # build parameters list for 'build_ip_lookup' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_ips, name="build_ip_lookup")

    return

"""
Search Palo Alto Networks firewall logs for any events with threat-related ip addresses in the dest_ip field
"""
def search_splunk_for_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('search_splunk_for_ips() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_ips' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_ips' call
    parameters.append({
        'query': "sourcetype=pan:t* ((earliest=-1d latest=now)) |eval IP=dest_ip | lookup huntip.csv IP OUTPUT RC | search RC>10",
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_ips_callback, name="search_splunk_for_ips", parent_action=action)

    return

def search_splunk_for_ips_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('search_splunk_for_ips_callback() called')
    
    join_Send_email_if_related_entities_are_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    recorded_future_threat_hunting_block_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Ask an analyst whether the discovered related IP addresses should be blocked
"""
def recorded_future_threat_hunting_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('recorded_future_threat_hunting_block_ip() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Do you want to add the following IP(s) to the block IP block list:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "search_splunk_for_ips:action_result.data.*.IP",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="recorded_future_threat_hunting_block_ip", parameters=parameters, response_types=response_types, callback=check_prompt)

    return

"""
Only proceed if the analyst approved the prompt
"""
def check_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_prompt() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["recorded_future_threat_hunting_block_ip:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_ip_to_block_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Add the IP address to a Phantom custom list, which can be tracked as a REST-accessible external block list by a firewall
"""
def add_ip_to_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_ip_to_block_list() called')

    results_data_1 = phantom.collect2(container=container, datapath=['search_splunk_for_ips:action_result.data.*.IP'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.add_list("IP Block List", results_item_1_0)

    return

"""
If any of the Splunk searches had any results, send an email to an analyst
"""
def Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Send_email_if_related_entities_are_found() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["search_splunk_for_ips:action_result.data.*.RC", ">", 0],
            ["search_splunk_for_domains:action_result.data.*.RC", ">", 0],
            ["search_splunk_for_files:action_result.data.*.RC", ">", 0],
            ["search_splunk_for_vulns:action_result.data.*.Rc", ">", 0],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        format_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_Send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Send_email_if_related_entities_are_found() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['search_splunk_for_ips', 'search_splunk_for_domains', 'search_splunk_for_files', 'search_splunk_for_vulns']):
        
        # call connected block "Send_email_if_related_entities_are_found"
        Send_email_if_related_entities_are_found(container=container, handle=handle)
    
    return

"""
Include the intelligence context and Splunk results in the email and link to the event in Phantom for the rest of the detail
"""
def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email() called')
    
    template = """The potentially malicious destination IP {0} with a Risk Score of {1} was identified and process by the Phantom playbook \"recorded_future_threat_hunting\".

Additional searches performed against various logs showed that the following related entities occurring in > 10  relations have been found in recent events:

IP addresses: {2}
domain names: {3}
file hashes: {4}
vulnerability identifiers: {5}

More details are available in Phantom: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.parameter.ip",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "search_splunk_for_ips:action_result.data.*.IP",
        "search_splunk_for_domains:action_result.data.*.domain",
        "search_splunk_for_files:action_result.data.*.hash",
        "search_splunk_for_vulns:action_result.data.*.vuln",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    send_email_1(container=container)

    return

"""
Send the formatted email to a hard-coded recipient
"""
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'cc': "",
        'to': "recipient@example.com",
        'bcc': "",
        'body': formatted_data_1,
        'from': "sender@example.com",
        'headers': "",
        'subject': "Malicous IP with related entities found in Splunk",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

"""
Build a Splunk query to turn a list of related entities from Recorded Future into a lookup table that can be used for threat hunting across any sourcetype or data model
"""
def format_related_domain_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_related_domain_lookup() called')
    
    template = """| makeresults | eval domain=\"{0}\" | makemv domain delim=\", \" | mvexpand domain | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntdomain.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_4:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_4:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_related_domain_lookup")

    build_domain_lookup(container=container)

    return

"""
Run the Splunk query that creates the lookup file
"""
def build_domain_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_domain_lookup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'build_domain_lookup' call
    formatted_data_1 = phantom.get_format_data(name='format_related_domain_lookup')

    parameters = []
    
    # build parameters list for 'build_domain_lookup' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_domains, name="build_domain_lookup")

    return

"""
Build a Splunk query to turn a list of related entities from Recorded Future into a lookup table that can be used for threat hunting across any sourcetype or data model
"""
def format_related_hash_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_related_hash_lookup() called')
    
    template = """| makeresults | eval hash=\"{0}\" | makemv hash delim=\", \" | mvexpand hash | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup hunthash.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_1:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_1:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_related_hash_lookup")

    build_hash_lookup(container=container)

    return

"""
Run the Splunk query that creates the lookup file
"""
def build_hash_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_hash_lookup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'build_hash_lookup' call
    formatted_data_1 = phantom.get_format_data(name='format_related_hash_lookup')

    parameters = []
    
    # build parameters list for 'build_hash_lookup' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_files, name="build_hash_lookup")

    return

"""
Build a Splunk query to turn a list of related entities from Recorded Future into a lookup table that can be used for threat hunting across any sourcetype or data model
"""
def format_related_vuln_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_related_vuln_lookup() called')
    
    template = """| makeresults | eval vuln=\"{0}\" | makemv vuln delim=\", \" | mvexpand vuln | appendcols [| makeresults | eval RC=\"{1}\" | makemv RC delim=\", \" | mvexpand RC ] | outputlookup huntvuln.csv"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Entity_Type_Filter:condition_2:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "filtered-data:Entity_Type_Filter:condition_2:ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_related_vuln_lookup")

    build_vuln_lookup(container=container)

    return

"""
Run the Splunk query that creates the lookup file
"""
def build_vuln_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_vuln_lookup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'build_vuln_lookup' call
    formatted_data_1 = phantom.get_format_data(name='format_related_vuln_lookup')

    parameters = []
    
    # build parameters list for 'build_vuln_lookup' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=search_splunk_for_vulns, name="build_vuln_lookup")

    return

"""
Search Palo Alto Networks threat logs for any events with threat-related domain names in the dest_hostname field
"""
def search_splunk_for_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('search_splunk_for_domains() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_domains' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_domains' call
    parameters.append({
        'query': "sourcetype=pan:threat ((earliest=-1d latest=now)) |eval domain=dest_hostname | lookup huntdomain.csv domain OUTPUT RC | search RC>10",
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_domains", parent_action=action)

    return

"""
Search Symantec Endpoint Protection logs for sightings of threat-related file hashes
"""
def search_splunk_for_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('search_splunk_for_files() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_files' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_files' call
    parameters.append({
        'query': "index=main sourcetype=symantec:ep:risk:file ((earliest=-1d latest=now)) |eval hash=file_hash | lookup hunthash.csv hash OUTPUT RC | search RC>10",
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_files", parent_action=action)

    return

"""
Search Tenable vulnerability scanning logs for any vulnerabilities related to the initial IP addresses
"""
def search_splunk_for_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('search_splunk_for_vulns() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_splunk_for_vulns' call

    parameters = []
    
    # build parameters list for 'search_splunk_for_vulns' call
    parameters.append({
        'query': "index=main sourcetype=\"tenable:sc:vuln\" ((earliest=-7d latest=now)) |eval vuln=cve | lookup huntvuln.csv vuln OUTPUT RC | search RC>10",
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_Send_email_if_related_entities_are_found, name="search_splunk_for_vulns", parent_action=action)

    return

"""
Query for the full context about the IP address and related entities from Recorded Future
"""
def ip_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_intelligence_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_intelligence_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_intelligence_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="ip intelligence", parameters=parameters, assets=['recorded_future'], callback=Entity_Type_Filter, name="ip_intelligence_1")

    return

"""
Filter four common entity types into different Splunk searches
"""
def Entity_Type_Filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Entity_Type_Filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "Hash"],
        ],
        name="Entity_Type_Filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_related_hash_lookup(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "CyberVulnerability"],
        ],
        name="Entity_Type_Filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_related_vuln_lookup(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "IpAddress"],
        ],
        name="Entity_Type_Filter:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        format_related_ip_lookup(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.type", "==", "InternetDomainName"],
        ],
        name="Entity_Type_Filter:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        format_related_domain_lookup(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

"""
Query for the risk score from Recorded Future
"""
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['recorded_future'], callback=risk_score_threshold, name="ip_reputation_1")

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