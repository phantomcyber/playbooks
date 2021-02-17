"""
This playbook gets initiated by a Timer asset (setup for the Timer asset is in the Notes section below) every 30 minutes to query ExtraHop for any new DNS servers that have been seen on your network in the last 30 minutes.  If one or more new DNS servers are discovered then the playbook will automatically initiate a Nessus endpoint scan on the IP of the new DNS server.  In addition the playbook will retrieve the following information about the new dns server:
  - ExtraHop device object
  - List of peer devices communicated with in the last 30 minutes
  - List of client and server protocols spoken in the last 30 minutes
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_devices_1' block
    get_devices_1(container=container)

    return

"""
Query ExtraHop for any new DNS servers that have been seen on your network in the last 30 minutes
"""
def get_devices_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_devices_1() called')

    # collect data for 'get_devices_1' call

    parameters = []
    
    # build parameters list for 'get_devices_1' call
    parameters.append({
        'minutes': 30,
        'activity_type': "dns_server",
    })

    phantom.act(action="get devices", parameters=parameters, assets=['extrahop'], callback=decision_1, name="get_devices_1")

    return

"""
Only initiate a scan on returned devices that have an IP Address
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_devices_1:action_result.data.*.ipaddr4", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        list_nessus_policies(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Get more details about an ExtraHop device given its IP address. Details include MAC address, dhcp name, first discovered time, device type, and more
"""
def get_device_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_device_info_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_devices_1:action_result.data.*.ipaddr4', 'get_devices_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_device_info_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get device info", parameters=parameters, assets=['extrahop'], callback=get_device_info_1_callback, name="get_device_info_1")

    return

def get_device_info_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_device_info_1_callback() called')
    
    get_peers_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_protocols_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Retrieves a list of all of the protocols that a device communicated over the last 30 minutes
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
Retrieves a list of all of the peers that a device communicated with in the last 30 minutes
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
                'peer_role': "any",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="get peers", parameters=parameters, assets=['extrahop'], name="get_peers_1", parent_action=action)

    return

"""
Initiate a Nessus scan on the new dns server
"""
def scan_endpoint_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('scan_endpoint_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'scan_endpoint_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_devices_1:action_result.data.*.ipaddr4', 'get_devices_1:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Nessus_Policy_Name:condition_1:list_nessus_policies:action_result.data.*.id", "filtered-data:Nessus_Policy_Name:condition_1:list_nessus_policies:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'scan_endpoint_1' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if filtered_results_item_1[0] and results_item_1[0]:
                parameters.append({
                    'policy_id': filtered_results_item_1[0],
                    'target_to_scan': results_item_1[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': filtered_results_item_1[1]},
                })

    phantom.act(action="scan endpoint", parameters=parameters, assets=['nessus scanner'], name="scan_endpoint_1")

    return

"""
(Requires Configuration) Filter your Nessus policies by Name and determine the corresponding Nessus policy id.
Fill this value in with the Name of the desired Nessus policy to scan the new dns server with.
"""
def Nessus_Policy_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Nessus_Policy_Name() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_nessus_policies:action_result.data.*.name", "==", ""],
        ],
        name="Nessus_Policy_Name:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        scan_endpoint_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
List the available Nessus scan policies
"""
def list_nessus_policies(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_nessus_policies() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act(action="list policies", parameters=parameters, assets=['nessus scanner'], callback=Nessus_Policy_Name, name="list_nessus_policies")

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