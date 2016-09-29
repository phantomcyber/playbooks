import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

"""
This playbook investigates and remediates phishing emails with Admin approval.
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
        vault_items = phantom.Vault.get_file_info(container_id=container['id'])
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
        domain_reputation(container=container)
    if ips:
    # call 'ip_reputation_1' block
        ip_reputation_1(container=container)
    if domains:
    # call 'whois_infoDomain' block
        whois_infoDomain(container=container)
    if ips:
    # call 'whois_infoIP' block
        whois_infoIP(container=container)
    if ips:
    # call 'geolocate_ip_1' block
        geolocate_ip_1(container=container)

    return

def whois_infoIP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_infoIP' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_infoIP' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois ip", parameters=parameters, assets=['domaintools'], name="whois_infoIP")    
    else:
        phantom.error("'whois_infoIP' will not be executed due to lack of parameters")
    
    return

def whois_infoDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_infoDomain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_infoDomain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois domain", parameters=parameters, assets=['whois'], name="whois_infoDomain")    
    else:
        phantom.error("'whois_infoDomain' will not be executed due to lack of parameters")
    
    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

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

    if parameters:
        phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=decision_10, name="geolocate_ip_1")    
    else:
        phantom.error("'geolocate_ip_1' will not be executed due to lack of parameters")
    
    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

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

    if parameters:
        phantom.act("ip reputation", parameters=parameters, assets=['virustotal_private'], callback=decision_8, name="ip_reputation_1")    
    else:
        phantom.error("'ip_reputation_1' will not be executed due to lack of parameters")
    
    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.detected_urls", ">=", 1],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation:action_result.status", "==", "MALICIOUS"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

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

    if parameters:
        phantom.act("file reputation", parameters=parameters, assets=['virustotal_private'], callback=decision_1, name="file_reputation_1")    
    else:
        phantom.error("'file_reputation_1' will not be executed due to lack of parameters")
    
    return

def domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'domain_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("domain reputation", parameters=parameters, assets=['opendns_investigate'], callback=decision_5, name="domain_reputation")    
    else:
        phantom.error("'domain_reputation' will not be executed due to lack of parameters")
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.summary.malware", "==", "yes"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

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

    if parameters:
        phantom.act("url reputation", parameters=parameters, assets=['virustotal_private'], callback=decision_4, name="url_reputation_1")    
    else:
        phantom.error("'url_reputation_1' will not be executed due to lack of parameters")
    
    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", "<=", 3],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">", 3],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceCustomString6', 'artifact:*.id'])
    vault_items = phantom.Vault.get_file_info(container_id=container['id'])

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for vault_item in vault_items:
        if vault_item['vault_id']:
            parameters.append({
                'file_name': "",
                'vault_id': vault_item['vault_id'],
            })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=['wildfire'], callback=decision_3, name="detonate_file_1")    
    else:
        phantom.error("'detonate_file_1' will not be executed due to lack of parameters")
    
    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.data.*.positives", ">=", 1],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_screenshot_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.data.*.positives", "<", 1],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        detonate_url_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.data.*.resource', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("detonate url", parameters=parameters, assets=['threatgrid'], callback=decision_6, name="detonate_url_1")    
    else:
        phantom.error("'detonate_url_1' will not be executed due to lack of parameters")
    
    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_url_1:action_result.data.*.threat.max-confidence", "==", 50],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        attribution(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_file_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["file_reputation_1:filtered-action_result.data.*.sha256", "file_reputation_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'hash': filtered_results_item_1[0],
                'type': "",
                'range': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    if parameters:
        phantom.act("hunt file", parameters=parameters, assets=['cbprotect','carbonblack','cylance_1'], callback=decision_2, name="hunt_file_1")    
    else:
        phantom.error("'hunt_file_1' will not be executed due to lack of parameters")
    
    return

##- special functions for hunt_file_1

def join_hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_1','detonate_file_1' ]):

        # call connected block "hunt_file_1"
        hunt_file_1(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_file_1:action_result.data.*.computerId", "!=", "\"NULL\""],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_sysinfo(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def attribution(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'attribution' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.requestURL', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'attribution' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'url': filtered_container_item[0],
            })

    if parameters:
        phantom.act("hunt url", parameters=parameters, assets=['isightpartners'], callback=get_screenshot_1, name="attribution")    
    else:
        phantom.error("'attribution' will not be executed due to lack of parameters")
    
    return

def IP_Domain_Rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Domain_Rep' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_ip_1:action_result.summary.hostname', 'lookup_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'IP_Domain_Rep' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("domain reputation", parameters=parameters, assets=['opendns_investigate'], callback=decision_11, name="IP_Domain_Rep", parent_action=action)    
    else:
        phantom.error("'IP_Domain_Rep' will not be executed due to lack of parameters")
    
    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["IP_Domain_Rep:action_result.summary.domain_status", "==", "MALICIOUS"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_sysinfo(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
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

    if parameters:
        phantom.act("get system attributes", parameters=parameters, assets=['domainctrl1'], callback=prompt_1, name="get_sysinfo")    
    else:
        phantom.error("'get_sysinfo' will not be executed due to lack of parameters")
    
    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "in", "Burma,China,Eretrea,Iran,North Korea,Saudi Arabia,Sudan,Turkmenistan,Uzbekistan"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_ip_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["ip_reputation_1:filtered-action_result.parameter.ip", "ip_reputation_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'lookup_ip_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    if parameters:
        phantom.act("lookup ip", parameters=parameters, assets=['dns'], callback=IP_Domain_Rep, name="lookup_ip_1")    
    else:
        phantom.error("'lookup_ip_1' will not be executed due to lack of parameters")
    
    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.requestURL', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'url': filtered_container_item[0],
                'size': "",
            })

    if parameters:
        phantom.act("get screenshot", parameters=parameters, assets=['screenshot machine'], callback=prompt_1, name="get_screenshot_1")    
    else:
        phantom.error("'get_screenshot_1' will not be executed due to lack of parameters")
    
    return

##- special functions for get_screenshot_1

def join_get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'url_reputation_1','attribution' ]):

        # call connected block "get_screenshot_1"
        get_screenshot_1(container=container, handle=handle)
    
    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = "An email is being marked as a Phish attempt. Please inspect and approve so that Phantom can delete all instances of the phish from your mail server.  If you do not respond within 6 hours (360 Minutes) the email will _NOT_ be deleted. If you respond (any response) will result in the subsequent removal of the phish from all mailboxes on your mail server. All enrichment data is in MIssion Control for your review."

    phantom.prompt(user=user, message=message, respond_in_mins=360, name="prompt_1", callback=delete_email_2)

    return

##- special functions for prompt_1

def join_prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'get_sysinfo','get_screenshot_1','domain_reputation','IP_Domain_Rep','geolocate_ip_1' ]):

        # call connected block "prompt_1"
        prompt_1(container=container, handle=handle)
    
    return

def delete_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['action_name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delete_email_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs1', 'artifact:*.id'])
    parameters = []
    
    # build parameters list for 'delete_email_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
            'ip_hostname': "exchange_server",
            'user': "",
            'subject': container['name'],
            'from': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("delete email", parameters=parameters, assets=['domainctrl1'], name="delete_email_2")    
    
    return

def on_finish(container, summary):

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
