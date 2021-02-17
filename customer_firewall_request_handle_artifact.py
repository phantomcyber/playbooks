"""
This playbook works in conjunction with "customer_firewall_request_parse_csv". After the first playbook parses the data into artifacts with the label "customer_request", this playbook takes the appropriate block/unblock actions. Between the combination of blocking or unblocking source or destination IP addresses there are four possible actions that can be taken.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_2' block
    filter_2(container=container)

    return

"""
Artifacts must have the label "customer_request" to be processed.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "customer_request"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Split processing based on "block_ip" vs. "unblock_ip" and "sourceAddress" vs. "destinationAddress".
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "==", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.action", "==", "block_ip"],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress", "==", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "!=", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.action", "==", "block_ip"],
        ],
        logical_operator='and',
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        block_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress", "!=", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "==", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.action", "==", "unblock_ip"],
        ],
        logical_operator='and',
        name="filter_1:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        unblock_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress", "==", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "!=", ""],
            ["filtered-data:filter_2:condition_1:artifact:*.cef.action", "==", "unblock_ip"],
        ],
        logical_operator='and',
        name="filter_1:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        unblock_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

"""
Unblock traffic by source IP address.
"""
def unblock_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unblock_src_ip() called')

    # collect data for 'unblock_src_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'unblock_src_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'ip': filtered_artifacts_item_1[0],
            'vsys': "",
            'is_source_address': True,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="unblock ip", parameters=parameters, assets=['pan'], name="unblock_src_ip")

    return

"""
Block traffic by destination IP address.
"""
def block_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_dst_ip() called')

    # collect data for 'block_dst_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_dst_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': False,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_dst_ip")

    return

"""
Unblock traffic by destination IP address.
"""
def unblock_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unblock_dst_ip() called')

    # collect data for 'unblock_dst_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'unblock_dst_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'ip': filtered_artifacts_item_1[0],
            'vsys': "",
            'is_source_address': False,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="unblock ip", parameters=parameters, assets=['pan'], name="unblock_dst_ip")

    return

"""
Block traffic by source IP address.
"""
def block_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_src_ip() called')

    # collect data for 'block_src_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_src_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_src_ip")

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