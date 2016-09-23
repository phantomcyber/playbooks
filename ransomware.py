import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

"""Ransomware detected on endpoint"""

# End - Global Code block
##############################

def on_start(container):
    
    # call 'get_file_1' block
    get_file_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.summary.malware", "==", "ransomware"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        block_hash_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        block_hash_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['list_connections_1:action_result.data.*.ip_addr', 'list_connections_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_ip_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'vsys': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("block ip", parameters=parameters, assets=['pan'], name="block_ip_2", parent_action=action)    
    else:
        phantom.error("'block_ip_2' will not be executed due to lack of parameters")
    
    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["detonate_file_1:filtered-action_result.data.*.task_info.report.*.network.tcp.*.@ip", "detonate_file_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                'vsys': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    if parameters:
        phantom.act("block ip", parameters=parameters, assets=['pan'], name="block_ip_1")    
    else:
        phantom.error("'block_ip_1' will not be executed due to lack of parameters")
    
    return

def terminate_process_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.sensor_id', 'hunt_file_1:action_result.data.*.process.results.*.process_pid', 'hunt_file_1:action_result.data.*.process.results.*.hostname', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'terminate_process_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1] and results_item_1[2]:
            parameters.append({
                'sensor_id': results_item_1[0],
                'pid': results_item_1[1],
                'ip_hostname': results_item_1[2],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[3]},
            })

    if parameters:
        phantom.act("terminate process", parameters=parameters, assets=['carbonblack'], name="terminate_process_2", parent_action=action)    
    else:
        phantom.error("'terminate_process_2' will not be executed due to lack of parameters")
    
    return

def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'quarantine_device_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.hostname', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'quarantine_device_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip_hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("quarantine device", parameters=parameters, assets=['carbonblack'], name="quarantine_device_1", parent_action=action)    
    else:
        phantom.error("'quarantine_device_1' will not be executed due to lack of parameters")
    
    return

def block_hash_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_3' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["detonate_file_1:filtered-action_result.data.*.task_info.report.*.process_list.process.*.file.create.*.@sha1", "detonate_file_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'block_hash_3' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'comment': "",
                'hash': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    if parameters:
        phantom.act("block hash", parameters=parameters, assets=['carbonblack'], name="block_hash_3")    
    else:
        phantom.error("'block_hash_3' will not be executed due to lack of parameters")
    
    return

def get_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'get_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("get file", parameters=parameters, assets=['cylance_1'], callback=detonate_file_1, name="get_file_1")    
    else:
        phantom.error("'get_file_1' will not be executed due to lack of parameters")
    
    return

def block_hash_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_4' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.fileHash', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'block_hash_4' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'comment': "",
                'hash': filtered_container_item[0],
            })

    if parameters:
        phantom.act("block hash", parameters=parameters, assets=['carbonblack'], name="block_hash_4")    
    else:
        phantom.error("'block_hash_4' will not be executed due to lack of parameters")
    
    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_file_1:action_result.summary.vault_id', 'get_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'file_name': "",
                'vault_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=['wildfire'], callback=decision_1, name="detonate_file_1", parent_action=action)    
    else:
        phantom.error("'detonate_file_1' will not be executed due to lack of parameters")
    
    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_file_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.fileHash', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'type': "",
                'range': "",
                'hash': filtered_container_item[0],
            })

    if parameters:
        phantom.act("hunt file", parameters=parameters, assets=['carbonblack'], callback=hunt_file_1_callback, name="hunt_file_1")    
    else:
        phantom.error("'hunt_file_1' will not be executed due to lack of parameters")
    
    return

##- special functions for hunt_file_1

def hunt_file_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    terminate_process_2(action=action, success=success, container=container, results=results, handle=handle)
    quarantine_device_1(action=action, success=success, container=container, results=results, handle=handle)
    disable_user_1(action=action, success=success, container=container, results=results, handle=handle)
    list_connections_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.id', 'hunt_file_1:action_result.data.*.process.results.*.process_name', 'hunt_file_1:action_result.data.*.process.results.*.process_pid', 'hunt_file_1:action_result.data.*.process.results.*.hostname', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1] and results_item_1[2] and results_item_1[3]:
            parameters.append({
                'carbonblack_process_id': results_item_1[0],
                'process_name': results_item_1[1],
                'pid': results_item_1[2],
                'ip_hostname': results_item_1[3],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[4]},
            })

    if parameters:
        phantom.act("list connections", parameters=parameters, assets=['carbonblack'], callback=block_ip_2, name="list_connections_1", parent_action=action)    
    else:
        phantom.error("'list_connections_1' will not be executed due to lack of parameters")
    
    return

def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'disable_user_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.username', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'disable_user_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("disable user", parameters=parameters, assets=['domainctrl1'], name="disable_user_1", parent_action=action)    
    else:
        phantom.error("'disable_user_1' will not be executed due to lack of parameters")
    
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