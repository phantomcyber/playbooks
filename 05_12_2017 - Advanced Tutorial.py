"""
This is the May 12 Tech Session Playbook that shows use of filter, decision, custom lists, prompts and scheduled actions.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import requests

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_2() called')
    
    # set container properties for: severity
    update_data = {
        "severity" : "high",
    }

    phantom.update(container, update_data)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 10],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:file_reputation_1:action_result.parameter.hash", "==", "artifact:*.cef.fileHash"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        terminate_process_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:test_machines"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'is_source_address': "",
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("block ip", parameters=parameters, assets=['pan'], callback=unblock_ip_1, name="block_ip_1", parent_action=action)    
    
    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:blocked_ips"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "sourabh@phantom.us"
    message = """shall we block the attacker IP  
{0} that is being connected to malware with hash 
{1} that has more 
{2} detections? NOTE: If you chose to block, it will be unblocked after 60 mins."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress",
        "filtered-data:filter_3:condition_1:artifact:*.cef.fileHash",
        "filtered-data:filter_2:condition_1:file_reputation_1:action_result.summary.positives",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, options=options, callback=decision_4)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        add_to_blocklist(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def add_to_blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_to_list() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_3:condition_1:artifact:*.id'])
    
    phantom_url = phantom.get_base_url()
    container_url = "{}/mission/{}".format(phantom_url, container['id'])
    
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            phantom.datastore_add('blocked_ips', [ filtered_artifacts_item_1[0], 'yes',  container_url ] )

    block_ip_1(action, success, container, results, handle, filtered_artifacts, filtered_results)
    return

def remove_from_blocklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('remove_from_blocklist() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'remove_from_blocklist' call
    ips_to_remove = phantom.collect2(container=container, datapath=['unblock_ip_1:action_result.parameter.ip'], action_results=results)
    
    phantom.debug("ips to remove: {}".format(ips_to_remove))
    del_rows = set()
    
    for ip in ips_to_remove:
        match = phantom.datastore_present('blocked_ips', [ip[0]], 0)
        #matches = match.get('matches', [])
        if 'matches' in match:
            matches = match['matches']
            for m in matches:
                idx = m.get('index', -1)
                if idx >= 0:
                    del_rows.add(idx)
    
    if del_rows:
        phantom.debug("deleting rows: {}".format(del_rows))
        data = { 'delete_rows': list(del_rows) }
        requests.post('https://127.0.0.1/rest/decided_list/blocked_ips', data=json.dumps(data), verify=False)

    return

def unblock_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('unblock_ip_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'unblock_ip_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_ip_1:action_result.parameter.ip', 'block_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'unblock_ip_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'is_source_address': "",
                'ip': results_item_1[0],
                'vsys': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })
    # calculate start time using delay of 1 minutes
    start_time = datetime.now() + timedelta(minutes=1)

    phantom.act("unblock ip", parameters=parameters, assets=['pan'], callback=remove_from_blocklist, start_time=start_time, name="unblock_ip_1", parent_action=action)    
    
    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['reversinglabs_private'], callback=filter_1, name="file_reputation_1")    
    
    return

def terminate_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('terminate_process_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fileName', 'filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'terminate_process_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0] and filtered_artifacts_item_1[1]:
            parameters.append({
                'name': filtered_artifacts_item_1[0],
                'ip_hostname': filtered_artifacts_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[2]},
            })

    #phantom.act("terminate process", parameters=parameters, assets=['tanium'], name="terminate_process_1")    
    
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