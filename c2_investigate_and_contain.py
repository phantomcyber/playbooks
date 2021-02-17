"""
This playbook is designed to perform the investigative and potential containment steps necessary to properly handle a command and control attack scenario. It will extract file and connection information from a compromised VM, enrich the information, then take containment actions depending on the significance of the information. Examples of significant information include files with threat scores greater than 50, IP addresses with reputation status of MALICIOUS, among other attributes.a
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import traceback

"""
This playbook is deigned to perform the investigative and potential containment steps necessary to properly handle a command and control attack scenario.  It will extract file and connection information from a compromised VM, enrich the information, then take containment actions depending on the significance of the information.  Examples of significant information include files with threat scores greater than 70, IP addresses with reputation status of MALICIOUS, among other attributes.
"""

def asset_configured(action):
    assets = phantom.get_assets(action=action)
    if assets:
        return True
    
    return False

def escalate(container):
    phantom.set_severity(container, "high")
    
def deescalate(container):
    phantom.set_severity(container, "low")
    phantom.close(container)
    
def deescalate_close_notify(container):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deescalate_close_notify' call

    container_id = container['id']
    phantom.deescalate(container)
    
    parameters = []
    
    # build parameters list for 'deescalate_close_notify' call
    parameters.append({
        'from': "",
        'to': "root@localhost",
        'subject': "Descalating and Closing Container ID: " + container['id'],
        'body': "The c2 investigate and contain playbook on the Phantom platform has completed and will be closing the container." +
                "Information about the container is as follows: \n Container ID: " + container['id'] + "\nContainer Label: " + container['label'] + "\nContainer Severity: " + container['severity'],
        'attachments': "",
    })

    if parameters:
        phantom.act("send email", parameters=parameters, assets=['smtp'], name="deescalate_close_notify")    
    else:
        phantom.error("'deescalate_close_notify' will not be executed due to lack of parameters")
    
    return

def escalate_close_notify(container):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'escalate_close_notify' call

    parameters = []
    
    # build parameters list for 'escalate_close_notify' call
    parameters.append({
        'body': "asdf",
        'to': "root@localhost",
        'from': "",
        'attachments': "",
        'subject': "Escalating and closing",
    })

    if parameters:
        phantom.act("send email", parameters=parameters, assets=['smtp'], name="escalate_close_notify")    
    else:
        phantom.error("'escalate_close_notify' will not be executed due to lack of parameters")
    
    return

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    # call 'hunt_ip_1' block
    hunt_ip_1(container=container)

    # call 'whois_ip_1' block
    whois_ip_1(container=container)

    # call 'list_vms_1' block
    list_vms_1(container=container)

    return

def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip_1() called')

    # collect data for 'whois_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], name="whois_ip_1")

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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_filter_4, name="geolocate_ip_1")

    return

def deescalate_close_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    deescalate_close_notify(container)
    
    return

def deescalate_close_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    deescalate_close_notify(container)
    
    return

def terminate_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('terminate_process_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['find_malware_1:action_result.data.*.pid', 'find_malware_1:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['snapshot_vm_1:action_result.data.*.host', 'snapshot_vm_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'terminate_process_1' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0]:
                parameters.append({
                    'pid': results_item_1[0],
                    'sensor_id': "",
                    'ip_hostname': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="terminate process", parameters=parameters, assets=['carbonblack'], callback=escalate_close_container2, name="terminate_process_1", parent_action=action)

    return

def deescalate_close_container1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    deescalate_close_notify(container)
    
    return

def escalate_close_container_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    escalate_close_notify(container)
    
    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_vms_1:action_result.data.*.ip", "==", "artifact:*.cef.sourceAddress"],
            ["list_vms_1:action_result.data.*.state", "==", "running"],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def list_vms_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_vms_1() called')

    parameters = []

    phantom.act(action="list vms", parameters=parameters, assets=['vmwarevsphere'], callback=filter_1, name="list_vms_1")

    return

def find_malware_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('find_malware_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'find_malware_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['snapshot_vm_1:action_result.data.*.vault_id', 'snapshot_vm_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'find_malware_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'profile': "",
                'vault_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="find malware", parameters=parameters, assets=['volatility'], callback=filter_5, name="find_malware_1", parent_action=action)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_2:detonate_file_3:action_result.data.*.report.disk.mbr.hashes.orig.md5", "==", "artifact:*.cef.fileHash"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_1' call
    passed_filtered_artifact_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.fileHash', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'block_hash_1' call
    for passed_filtered_artifact_item in passed_filtered_artifact_data:
        parameters.append({
            'hash': passed_filtered_artifact_item[0],
            'comment': "",
        })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=terminate_process_1, name="block_hash_1")

    return

def escalate_close_container2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    escalate_close_notify(container)

    return

def hunt_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_ip_1() called')

    # collect data for 'hunt_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'scope': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="hunt ip", parameters=parameters, assets=['autofocus'], name="hunt_ip_1")

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

    phantom.act(action="ip reputation", parameters=parameters, assets=['opendns_investigate'], callback=join_filter_4, name="ip_reputation_1")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.ip_status", "==", "MALICIOUS"],
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "!=", "US"],
        ],
        logical_operator='or',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.ip_status", "!=", "MALICIOUS"],
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "==", "US"],
        ],
        logical_operator='and',
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        deescalate_close_container(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_4() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['ip_reputation_1', 'geolocate_ip_1']):
        
        # call connected block "filter_4"
        filter_4(container=container, handle=handle)
    
    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "",
                'is_source_address': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], callback=escalate_close_container_2, name="block_ip_1")

    return

def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["list_vms_1:filtered-action_result.data.*.vmx_path", "list_vms_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'download': "",
                'vmx_path': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="snapshot vm", parameters=parameters, assets=['vmwarevsphere'], callback=find_malware_1, name="snapshot_vm_1")

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["find_malware_1:action_result.summary.possibly_mal_instances", ">", 0],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_process_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["find_malware_1:action_result.summary.possibly_mal_instances", "<", 0],
        ],
        name="filter_5:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["find_malware_1:action_result.summary.possibly_mal_instances", "==", 0],
        ],
        name="filter_5:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        deescalate_close_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

def get_process_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_process_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_process_file_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['find_malware_1:action_result.data.*.pid', 'find_malware_1:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['snapshot_vm_1:action_result.summary.vol_profile_used', 'snapshot_vm_1:action_result.data.*.vault_id', 'snapshot_vm_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_process_file_1' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[1]:
                parameters.append({
                    'ph': "",
                    'pid': results_item_1[0],
                    'profile': results_item_2[0],
                    'vault_id': results_item_2[1],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="get process file", parameters=parameters, assets=['volatility'], callback=detonate_file_3, name="get_process_file_1")

    return

def detonate_file_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonate_file_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_process_file_1:action_result.data.*.vault_id', 'get_process_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_file_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'vm': "",
                'private': "",
                'playbook': "",
                'vault_id': results_item_1[0],
                'file_name': "",
                'force_analysis': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['threatgrid'], callback=join_filter_2, name="detonate_file_3", parent_action=action)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_3:action_result.data.*.threat.score", "==", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_report_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_3:action_result.data.*.threat.score", "!=", ""],
            ["detonate_file_3:action_result.data.*.threat.score", ">", 50],
        ],
        logical_operator='and',
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_3:action_result.data.*.threat.score", "!=", ""],
            ["detonate_file_3:action_result.data.*.threat.score", "<=", 50],
        ],
        logical_operator='and',
        name="filter_2:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        deescalate_close_container1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

def join_filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['detonate_file_3', 'get_report_1']):
        
        # call connected block "filter_2"
        filter_2(container=container, handle=handle)
    
    return

def get_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_report_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_report_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['detonate_file_3:action_result.summary.id', 'detonate_file_3:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_report_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })
    # calculate start time using delay of 10 minutes
    start_time = datetime.now() + timedelta(minutes=10)

    phantom.act(action="get report", parameters=parameters, assets=['threatgrid'], callback=join_filter_2, start_time=start_time, name="get_report_1")

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