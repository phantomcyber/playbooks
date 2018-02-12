"""
This playbook retrieves IP addresses, domains, and file hashes, blocks them on various services, and adds them to specific blacklists as custom lists.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    # call 'filter_3' block
    filter_3(container=container)

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_1() called')

    # collect data for 'block_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_4:condition_1:artifact:*.id'])

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

    phantom.act("block ip", parameters=parameters, assets=['pan'], callback=Add_to_IP_blacklist, name="block_ip_1")

    return

def block_hash_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_hash_2() called')

    # collect data for 'block_hash_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_6:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_hash_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'comment': "",
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("block hash", parameters=parameters, assets=['carbonblack'], callback=Add_hash_to_blacklist, name="block_hash_2")

    return

def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_domain_1() called')

    # collect data for 'block_domain_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_domain_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'disable_safeguards': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("block domain", parameters=parameters, assets=['opendns_umbrella'], callback=Add_domain_to_blacklist, name="block_domain_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_6(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain", "not in", "custom_list:domain_blacklist"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_3:condition_1:artifact:*.cef.fileHash", "not in", "custom_list:filehash_blacklist"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Add_hash_to_blacklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_hash_to_blacklist() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_hash_to_blacklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_hash_2:action_result.parameter.hash', 'block_hash_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Add_hash_to_blacklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:filehash_blacklist",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("add listitem", parameters=parameters, assets=['helper'], name="Add_hash_to_blacklist", parent_action=action)

    return

def Add_domain_to_blacklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_domain_to_blacklist() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_domain_to_blacklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_domain_1:action_result.parameter.domain', 'block_domain_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Add_domain_to_blacklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:domain_blacklist",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("add listitem", parameters=parameters, assets=['helper'], name="Add_domain_to_blacklist", parent_action=action)

    return

def Add_to_IP_blacklist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Add_to_IP_blacklist() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_to_IP_blacklist' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_ip_1:action_result.parameter.ip', 'block_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Add_to_IP_blacklist' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'list': "custom_list:blacklisted_ips",
                'create': True,
                'new_row': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("add listitem", parameters=parameters, assets=['helper'], name="Add_to_IP_blacklist", parent_action=action)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:ip_address_blacklist"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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