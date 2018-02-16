"""
Process requests created by Vectra to either block or unblock the specified IP address on a Palo Alto Networks Firewall.

Author: Chris Johnson
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
Determine whether the Vectra request specifies a block or an unblock.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')
    
    source_data_identifier_value = container.get('source_data_identifier', None)
    source_data_identifier_value = container.get('source_data_identifier', None)

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["vectra_block_request", "in", source_data_identifier_value],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        block_ip_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["vectra_unblock_request", "in", source_data_identifier_value],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        unblock_ip_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

"""
Block the specified source IP address for the device.
"""
def block_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_2() called')

    # collect data for 'block_ip_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dvc', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("block ip", parameters=parameters, assets=['pan'], name="block_ip_2")

    return

"""
Unblock the specified source IP address for the device.
"""
def unblock_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('unblock_ip_2() called')

    # collect data for 'unblock_ip_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dvc', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'unblock_ip_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("unblock ip", parameters=parameters, assets=['pan'], name="unblock_ip_2")

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