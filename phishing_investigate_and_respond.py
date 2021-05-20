"""
This playbook investigates and remediates phishing emails with Admin approval.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

"""
This playbook is deigned to perform the investigative steps necessary to investigate a potential Phishing attempt. It will process File attachments, IPs, domains,  and URLs. If there is a positive, the Admin user group on Phantom will have 6 hours to respond to the prompt in order to have the email deleted from the exchange server.
"""

def test_params(container, datapath, key_name):
    params = []
    items = set(phantom.collect(container, datapath, scope='all'))
    for item in items:
        params.append({key_name:item}) 
    return params

# End - Global Code block
##############################

def on_start(container):
    urls = test_params(container, 'artifact:*.cef.requestURL', 'url')
    domains = test_params(container,'artifact:*.cef.destinationDnsDomain', 'domain') 
    ips = test_params(container, 'artifact:*.cef.destinationAddress', 'ip') 
    file_hashs = test_params(container, 'artifact:*.cef.cs6', 'hash')
    #if no file hashes this way, lets see if there is a vault item that has been added manually)
    if not file_hashs:
        success, message, vault_items = phantom.vault_info(container_id=container['id'])
        hashes = []
        for vault_item in vault_items:            
            hashes.append({'hash': vault_item['metadata']['sha256']})
    if file_hashs:
    # call 'file_reputation_1' block
        file_reputation_1(container=container)
    if urls:
    # call 'url_reputation_1' block
        url_reputation_1(container=container)
    if domains:
    # call 'domain_reputation_1' block
        domain_reputation_1(container=container)
    if ips:
    # call 'ip_reputation_1' block
        ip_reputation_1(container=container)
    if domains:
    # call 'whois_infoDomain' block
        whois_domain(container=container)
    if ips:
    # call 'whois_infoIP' block
        whois_ip(container=container)
    if ips:
    # call 'geolocate_ip_1' block
        geolocate_ip_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_10, name="geolocate_ip_1")

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.detected_urls", ">=", 1],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.status", "==", "MALICIOUS"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_13() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.parameter.ip", "==", "artifact:*.cef.destinationAddress"],
        ],
        name="filter_13:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceCustomString6', 'artifact:*.id'])
    success, message, vault_items = phantom.vault_info(container_id=container['id'])

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for vault_item in vault_items:
        if vault_item['vault_id']:
            parameters.append({
                'file_name': "",
                'vault_id': vault_item['vault_id'],
            })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=['wildfire'], callback=filter_3, name="detonate_file_1")    
    else:
        phantom.error("'detonate_file_1' will not be executed due to lack of parameters")
    
    return

def get_sysinfo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_sysinfo() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_sysinfo' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.hostname', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_sysinfo' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'fields': "",
                'hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get system attributes", parameters=parameters, assets=['domainctrl1'], callback=join_prompt_1, name="get_sysinfo")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_file_1:action_result.data.*.computerId", "!=", "\"NULL\""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_sysinfo(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_11() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_2:action_result.summary.domain_status", "==", "MALICIOUS"],
        ],
        name="filter_11:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_15() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.parameter.domain", "==", "artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_15:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs6', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=filter_1, name="file_reputation_1")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=filter_4, name="url_reputation_1")

    return

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

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=filter_8, name="ip_reputation_1")

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonate_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.data.*.resource', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                'playbook': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="detonate url", parameters=parameters, assets=['threatgrid'], callback=filter_6, name="detonate_url_1")

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_url_1:action_result.data.*.threat.max-confidence", ">", 50],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        attribution(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def attribution(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('attribution() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'attribution' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_6:condition_1:detonate_url_1:action_result.parameter.url", "filtered-data:filter_6:condition_1:detonate_url_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'attribution' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'url': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="hunt url", parameters=parameters, assets=['isightpartners'], callback=join_get_screenshot_1, name="attribution")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.data.*.positives", ">=", 1],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_get_screenshot_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.data.*.positives", "<", 1],
        ],
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        detonate_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:url_reputation_1:action_result.parameter.url", "filtered-data:filter_4:condition_1:url_reputation_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'url': filtered_results_item_1[0],
                'size': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshot machine'], callback=join_prompt_1, name="get_screenshot_1")

    return

def join_get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_get_screenshot_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_get_screenshot_1_called'):
        return

    # no callbacks to check, call connected block "get_screenshot_1"
    phantom.save_run_data(key='join_get_screenshot_1_called', value='get_screenshot_1', auto=True)

    get_screenshot_1(container=container, handle=handle)
    
    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.summary.malware", "==", "yes"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", "<=", 3],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">", 3],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_file_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["file_reputation_1:filtered-action_result.data.*.sha256", "file_reputation_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'hash': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="hunt file", parameters=parameters, assets=['cbprotect'], callback=filter_2, name="hunt_file_1")

    return

def join_hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_hunt_file_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_hunt_file_1_called'):
        return

    # no callbacks to check, call connected block "hunt_file_1"
    phantom.save_run_data(key='join_hunt_file_1_called', value='hunt_file_1', auto=True)

    hunt_file_1(container=container, handle=handle)
    
    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "YES"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        delete_email_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """An email is being marked as a Phish attempt. Please inspect and approve so that Phantom can delete all instances of the phish from your mail server.  If you do not respond within 6 hours (360 Minutes) the email will _NOT_ be deleted. If you respond \"Yes\" Phantom will start the removal of the phish from all mailboxes on your mail server. All enrichment data is in MIssion Control for your review."""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=360, name="prompt_1", response_types=response_types, callback=decision_1)

    return

def join_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_prompt_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_prompt_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['domain_reputation_2', 'domain_reputation_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_prompt_1_called', value='prompt_1')
        
        # call connected block "prompt_1"
        prompt_1(container=container, handle=handle)
    
    return

def filter_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_14() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:artifact:*.cef.destinationAddress", "==", "artifact:*.cef.destinationAddress"],
        ],
        name="filter_14:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_10() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "in", "Burma,China,Eretrea,Iran,North Korea,Saudi Arabia,Sudan,Turkmenistan,Uzbekistan"],
        ],
        name="filter_10:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_14(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def whois_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain() called')

    # collect data for 'whois_domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], name="whois_domain")

    return

def whois_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip() called')

    # collect data for 'whois_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['domaintools'], name="whois_ip")

    return

def delete_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'delete_email_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'delete_email_2' call
    for container_item in container_data:
        parameters.append({
            'from': container_item[0],
            'user': "",
            'subject': name_value,
            'ip_hostname': "exchange_server",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="delete email", parameters=parameters, assets=['domainctrl1'], name="delete_email_2")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['opendns_investigate'], callback=filter_5, name="domain_reputation_1")

    return

def domain_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_ip_1:action_result.summary.hostname', 'lookup_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['opendns_investigate'], callback=filter_11, name="domain_reputation_2", parent_action=action)

    return

def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_ip_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["ip_reputation_1:filtered-action_result.parameter.ip", "ip_reputation_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'lookup_ip_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'ip': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['dns'], callback=domain_reputation_2, name="lookup_ip_1")

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