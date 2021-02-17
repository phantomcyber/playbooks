"""
The playbook automates the IP and URL indicator enrichment process using ThreatQuotient's threat library and other reputation tools. The playbook will also post back threat intelligence data to ThreatQuotient if it does not already exist. Finally, block rules are deployed if URL or IP threat scoring thresholds are exceeded. This playbook was constructed for the Phantom Tech Session held on 03/24/2017 with ThreatQuotient.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import ipaddress

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'create_event_1' block
    create_event_1(container=container)

    # call 'filter_6' block
    filter_6(container=container)

    return

def block_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_url_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_8:condition_1:src_ip_reputation_VT:action_result.data.*.detected_urls.*.urldata.*.detected_urls.*.url", "filtered-data:filter_8:condition_1:src_ip_reputation_VT:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'block_url_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ph': "",
                'url': filtered_results_item_1[0],
                'vsys': "",
                'sec_policy': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="block url", parameters=parameters, assets=['pan'], name="block_url_2", parent_action=action)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "not in", "custom_list:internal range"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dst_ip_reputation_TQ(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:internal range"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        src_ip_reputation_TQ(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.vaultId", "!=", ""],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        upload_file_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_src_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_src_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_src_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_src_ip")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["dst_ip_reputation_TQ:action_result.message", "==", "ThreatQ query did not return any information"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_dst_IP_ioc(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["dst_ip_reputation_TQ:action_result.message", "==", "SUCCESS"],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)
        dst_ip_reputation_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_1:src_ip_reputation_TQ:action_result.data.*.status.name", "==", "Active"],
            ["filtered-data:filter_3:condition_1:src_ip_reputation_TQ:action_result.data.*.adversaries.*.name", "!=", ""],
        ],
        logical_operator='or',
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_2:dst_ip_reputation_TQ:action_result.data.*.status.name", "==", "Active"],
            ["filtered-data:filter_2:condition_2:dst_ip_reputation_TQ:action_result.data.*.adversaries.*.name", "!=", ""],
        ],
        logical_operator='or',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["src_ip_reputation_TQ:action_result.message", "==", "SUCCESS"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        src_ip_reputation_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["src_ip_reputation_TQ:action_result.message", "==", "ThreatQ query did not return any information"],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        create_src_IP_ioc(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["src_ip_reputation_VT:action_result.data.*.detected_urls.*.positives", ">=", 1],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        create_URL_ioc_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def create_URL_ioc_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_URL_ioc_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_URL_ioc_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_8:condition_1:src_ip_reputation_VT:action_result.data.*.detected_urls.*.urldata.*.detected_urls.*.urldata.*.detected_urls.*.urldata.*.detected_urls.*.url", "filtered-data:filter_8:condition_1:src_ip_reputation_VT:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'create_URL_ioc_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'indicator': filtered_results_item_1[0],
                'indicator_type': "URL",
                'indicator_status': "Review",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="create ioc", parameters=parameters, assets=['threatq'], callback=block_url_2, name="create_URL_ioc_2")

    return

def block_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_dst_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_dst_ip' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_dst_ip' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], name="block_dst_ip")

    return

def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['dst_ip_reputation_VT:action_result.data.*.detected_urls.*.url', 'dst_ip_reputation_VT:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ph': "",
                'url': results_item_1[0],
                'vsys': "",
                'sec_policy': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="block url", parameters=parameters, assets=['pan'], name="block_url_1", parent_action=action)

    return

def src_ip_reputation_TQ(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('src_ip_reputation_TQ() called')

    # collect data for 'src_ip_reputation_TQ' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'src_ip_reputation_TQ' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'query': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatq'], callback=filter_3, name="src_ip_reputation_TQ")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["dst_ip_reputation_VT:action_result.data.*.detected_urls.*.positives", ">=", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        create_URL_ioc_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def dst_ip_reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dst_ip_reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'dst_ip_reputation_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'dst_ip_reputation_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="dst_ip_reputation_VT")

    return

def src_ip_reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('src_ip_reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'src_ip_reputation_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'src_ip_reputation_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=filter_8, name="src_ip_reputation_VT")

    return

def create_src_IP_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_src_IP_ioc() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_src_IP_ioc' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'create_src_IP_ioc' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'indicator': filtered_artifacts_item_1[0],
                'indicator_type': "IP Address",
                'indicator_status': "Review",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="create ioc", parameters=parameters, assets=['threatq'], name="create_src_IP_ioc")

    return

def create_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_event_1() called')

    parameters = []

    phantom.act(action="create event", parameters=parameters, assets=['threatq'], name="create_event_1")

    return

def upload_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('upload_file_2() called')

    # collect data for 'upload_file_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'upload_file_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vault_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="upload file", parameters=parameters, assets=['threatq'], name="upload_file_2")

    return

def create_URL_ioc_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_URL_ioc_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_URL_ioc_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['dst_ip_reputation_VT:action_result.data.*.detected_urls.*.url', 'dst_ip_reputation_VT:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'create_URL_ioc_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'indicator': results_item_1[0],
                'indicator_type': "URL",
                'indicator_status': "Review",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="create ioc", parameters=parameters, assets=['threatq'], callback=block_url_1, name="create_URL_ioc_1")

    return

def create_dst_IP_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_dst_IP_ioc() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_dst_IP_ioc' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['dst_ip_reputation_TQ:artifact:*.cef.sourceAddress', 'dst_ip_reputation_TQ:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'create_dst_IP_ioc' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'indicator': inputs_item_1[0],
                'indicator_type': "IP Address",
                'indicator_status': "Review",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="create ioc", parameters=parameters, assets=['threatq'], name="create_dst_IP_ioc")

    return

def dst_ip_reputation_TQ(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dst_ip_reputation_TQ() called')

    # collect data for 'dst_ip_reputation_TQ' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'dst_ip_reputation_TQ' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'query': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatq'], callback=filter_2, name="dst_ip_reputation_TQ")

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