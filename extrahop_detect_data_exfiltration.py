"""
This playbook processes an ExtraHop Addy anomaly indicating potential data exfiltration on the network.  It first retrieves all of the peers acting as a client in the last 30 minutes for the device that triggered the anomaly.  Then it filters out private IP Addresses as defined in RFC1918.  Next it looks up IP reputation scores for each of the non-private IP Addresses that have communicated with the device that triggered the anomaly in the last 30 minutes. If a known-bad IP is found then that device will be tagged with "bad_ip_reputation" in ExtraHop and a Phantom task will be created to track further manual investigation of this event.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

"""
Look up all of the protocols the device that triggered the anomaly communicated in the last 30 minutes
"""
def get_protocols_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_protocols_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_protocols_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_1:action_result.data.*.ipaddr4', 'get_device_info_1:action_result.data.*.id', 'get_device_info_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_protocols_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'minutes': 30,
                'eh_api_id': results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="get protocols", parameters=parameters, assets=['extrahop'], name="get_protocols_1", parent_action=action)

    return

"""
Continue running this playbook only if the artifact label is "data_exfiltration"
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "data_exfiltration"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Get more details about an ExtraHop device given its IP address. Details include MAC address, dhcp name, first discovered time, device type, and more
"""
def get_device_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_1() called')

    # collect data for 'get_device_info_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_device_info_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get device info", parameters=parameters, assets=['extrahop'], callback=get_device_info_1_callback, name="get_device_info_1")

    return

def get_device_info_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_device_info_1_callback() called')
    
    get_peers_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_protocols_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Look up all of the peers acting as a client in the last 30 minutes for the device that triggered the anomaly
"""
def get_peers_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_peers_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_peers_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_1:action_result.data.*.ipaddr4', 'get_device_info_1:action_result.data.*.id', 'get_device_info_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_peers_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'minutes': 30,
                'protocol': "any",
                'eh_api_id': results_item_1[1],
                'peer_role': "client",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="get peers", parameters=parameters, assets=['extrahop'], callback=internal_ip_filter, name="get_peers_1", parent_action=action)

    return

"""
Assign a manual task to do further investigation into the Data Exfiltration anomaly.
"""
def task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_1() called')
    
    # set user and message variables for phantom.task call
    user = "admin"
    message = """ExtraHop Addy has detected a data exfiltration anomaly on your network and Phantom has confirmed via Anomali ThreatStream that the source address has connected with one or more known-bad external IP addresses in the last 30 minutes."""

    phantom.task(user=user, message=message, respond_in_mins=30, name="task_1")

    return

"""
Filter out private peers as defined by RFC 1918
"""
def internal_ip_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('internal_ip_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_peers_1:action_result.data.*.ipaddr4", "not in", "10.0.0.0/8"],
            ["get_peers_1:action_result.data.*.ipaddr4", "not in", "172.16.0.0/12"],
            ["get_peers_1:action_result.data.*.ipaddr4", "not in", "192.168.0.0/16"],
        ],
        logical_operator='and',
        name="internal_ip_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Tag the device in ExtraHop with the "bad_ip_reputation" tag
"""
def tag_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('tag_device_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'tag_device_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:linking_filter:condition_1:get_peers_1:action_result.data.*.ipaddr4", "filtered-data:linking_filter:condition_1:get_peers_1:action_result.data.*.id", "filtered-data:linking_filter:condition_1:get_peers_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'tag_device_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                'tag': "bad_ip_reputation",
                'eh_api_id': filtered_results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[2]},
            })

    phantom.act(action="tag device", parameters=parameters, assets=['extrahop'], name="tag_device_1")

    return

"""
(Requires Configuration) Only tag the device if the Threat Score and Confidence come back above certain thresholds
"""
def threat_score_thresholds(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('threat_score_thresholds() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.threatscore", ">", 1],
            ["ip_reputation_1:action_result.data.*.confidence", ">", 1],
        ],
        logical_operator='and',
        name="threat_score_thresholds:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        linking_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Link the filtered "ip reputation" results back to the "get peer" results so we can use the ip address and ExtraHop id in "tag device"
"""
def linking_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('linking_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:threat_score_thresholds:condition_1:ip_reputation_1:action_result.parameter.ip", "==", "get_peers_1:action_result.data.*.ipaddr4"],
        ],
        name="linking_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        tag_device_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        task_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Look up the IP reputation of all external peers acting as a client in the last 30 minutes for the device that triggered the anomaly
"""
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:internal_ip_filter:condition_1:get_peers_1:action_result.data.*.ipaddr4", "filtered-data:internal_ip_filter:condition_1:get_peers_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                'limit': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream'], callback=threat_score_thresholds, name="ip_reputation_1")

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