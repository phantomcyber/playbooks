"""
This playbook processes an ExtraHop detection of an internal database being accessed externally.  The playbook will block the corresponding client source IP Address on a Palo Alto Networks Firewall as well as retrieve the following information on both the client and server:
  - ExtraHop device objects
  - List of peer devices communicated with in the last 30 minutes
  - List of client and server protocols spoken in the last 30 minutes
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
Continue running this playbook only if the artifact label is "publicly_exposed_db"
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "publicly_exposed_db"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_db_device_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        get_client_device_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        block_client_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Get more details about the internal database server given its IP address. Details include MAC address, dhcp name, first discovered time, device type, and more
"""
def get_db_device_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_db_device_info() called')

    # collect data for 'get_db_device_info' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_db_device_info' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get device info", parameters=parameters, assets=['extrahop'], callback=get_db_device_info_callback, name="get_db_device_info")

    return

def get_db_device_info_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_db_device_info_callback() called')
    
    get_db_peers(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_db_protocols(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Get more details about the external client given its IP address. Details include MAC address, dhcp name, first discovered time, device type, and more
"""
def get_client_device_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_client_device_info() called')

    # collect data for 'get_client_device_info' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_client_device_info' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get device info", parameters=parameters, assets=['extrahop'], callback=get_client_device_info_callback, name="get_client_device_info")

    return

def get_client_device_info_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_client_device_info_callback() called')
    
    get_client_peers(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_client_protocols(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Retrieves a list of all of the peers that a device communicated with in the last 30 minutes
"""
def get_db_peers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_db_peers() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_db_peers' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_db_device_info:action_result.data.*.ipaddr4', 'get_db_device_info:action_result.data.*.id', 'get_db_device_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_db_peers' call
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

    phantom.act(action="get peers", parameters=parameters, assets=['extrahop'], name="get_db_peers", parent_action=action)

    return

"""
Retrieves a list of all of the protocols that a device communicated over the last 30 minutes
"""
def get_db_protocols(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_db_protocols() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_db_protocols' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_db_device_info:action_result.data.*.ipaddr4', 'get_db_device_info:action_result.data.*.id', 'get_db_device_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_db_protocols' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'minutes': 30,
                'eh_api_id': results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="get protocols", parameters=parameters, assets=['extrahop'], name="get_db_protocols", parent_action=action)

    return

"""
Retrieves a list of all of the peers that a device communicated with in the last 30 minutes
"""
def get_client_peers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_client_peers() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_client_peers' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_client_device_info:action_result.data.*.ipaddr4', 'get_client_device_info:action_result.data.*.id', 'get_client_device_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_client_peers' call
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

    phantom.act(action="get peers", parameters=parameters, assets=['extrahop'], name="get_client_peers", parent_action=action)

    return

"""
Retrieves a list of all of the protocols that a device communicated over the last 30 minutes
"""
def get_client_protocols(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_client_protocols() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_client_protocols' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_client_device_info:action_result.data.*.ipaddr4', 'get_client_device_info:action_result.data.*.id', 'get_client_device_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_client_protocols' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'minutes': 30,
                'eh_api_id': results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="get protocols", parameters=parameters, assets=['extrahop'], name="get_client_protocols", parent_action=action)

    return

"""
Block the source IP that is externally accessing an internal database on the Palo Alto Networks Firewall
"""
def block_client_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_client_ip() called')

    # collect data for 'block_client_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_client_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_client_ip")

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