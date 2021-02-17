"""
Process requests created by Vectra to either block or unblock the specified IP address on a Palo Alto Networks Firewall. If the detected device is a virtual machine and the request is to block the IP then a snapshot will be taken and a further check will be done to see if the virtual machine should be suspended.

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
Unblock the specified source IP address for the device.
"""
def unblock_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unblock_ip() called')

    # collect data for 'unblock_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dvc', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'unblock_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="unblock ip", parameters=parameters, assets=['pan'], name="unblock_ip")

    return

"""
Block the specified source IP address for the device.
"""
def block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip() called')

    # collect data for 'block_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dvc', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_ip")

    return

"""
Use the custom string provided by Vectra to determine if the detected device is a virtual machine.
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["virtual", "in", "artifact:*.cef.cs1"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    block_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Gather evidence for further analysis by taking a snapshot of the virtual machine's current state.
"""
def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')

    # collect data for 'snapshot_vm_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.cs2', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'download': True,
                'vmx_path': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="snapshot vm", parameters=parameters, assets=['vmwarevsphere'], callback=decision_3, name="snapshot_vm_1")

    return

"""
Use the category provided by Vectra to determine if the detected threat has been categorized as lateral movement and needs to be stopped immediately.
"""
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.category", "==", "lateral"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        suspend_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Immediately suspend the virtual machine to prevent further damage.
"""
def suspend_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('suspend_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'suspend_vm_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['snapshot_vm_1:action_result.parameter.vmx_path', 'snapshot_vm_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'suspend_vm_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'download': False,
                'vmx_path': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="suspend vm", parameters=parameters, assets=['vmwarevsphere'], name="suspend_vm_1")

    return

"""
Determine whether the Vectra request specifies a block or an unblock.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')
    
    source_data_identifier_value = container.get('source_data_identifier', None)
    source_data_identifier_value = container.get('source_data_identifier', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["vectra_block_request", "in", source_data_identifier_value],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["vectra_unblock_request", "in", source_data_identifier_value],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        unblock_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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