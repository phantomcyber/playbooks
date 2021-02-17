"""
This playbook proactively blocks high impact indicators ingested from PhishMe. It was constructed for the Phantom Tech Session held on 04/07/2017 with PhishMe.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_2' block
    decision_2(container=container)

    return

def set_severity_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_6() called')

    phantom.set_severity(container=container, severity="high")

    return

def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_11() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_11:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_12() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_12:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_10() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_10:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_13() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
        ],
        name="filter_13:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def ip_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="ip_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.severity", "==", "high"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_report_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_severity_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_7() called')

    phantom.set_severity(container=container, severity="high")

    return

def set_severity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_8() called')

    phantom.set_severity(container=container, severity="high")

    return

def domain_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="domain_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:url_filter:condition_1:artifact:*.cef.requestURL', 'filtered-data:url_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ph': "",
                'url': filtered_artifacts_item_1[0],
                'vsys': "",
                'sec_policy': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block url", parameters=parameters, assets=['pan'], callback=format_4, name="block_url_1")

    return

def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_domain_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:domain_filter:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:domain_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_domain_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                'disable_safeguards': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block domain", parameters=parameters, assets=['opendns_umbrella'], callback=format_3, name="block_domain_1")

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.severity", "==", "high"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        domain_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        url_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_hash_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_2:action_result.parameter.hash', 'file_reputation_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_hash_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                'comment': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=format_5, name="block_hash_3")

    return

def url_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.requestURL", "!=", ""],
        ],
        name="url_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_10:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_10:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=decision_9, name="ip_reputation_1")

    return

def file_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_9:condition_1:artifact:*.cef.fileHashMd5', 'filtered-data:filter_9:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=filter_5, name="file_reputation_2")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_11:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_11:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=decision_8, name="domain_reputation_1")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_12:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_12:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=decision_7, name="url_reputation_1")

    return

def set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_9() called')

    phantom.set_severity(container=container, severity="high")

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_2:summary.total_positives", ">=", 10],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_9() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
        ],
        name="filter_9:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:ip_filter:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:ip_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "",
                'is_source_address': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], callback=format_2, name="block_ip_1")

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:summary.total_positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:summary.total_positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:summary.total_positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_13:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_13:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=decision_6, name="file_reputation_1")

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:summary.total_positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_3() called')

    phantom.set_severity(container=container, severity="high")
    set_status_4(container=container)

    return

def join_set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_severity_3() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_severity_3_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['update_ticket_7']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_set_severity_3_called', value='set_severity_3')
        
        # call connected block "set_severity_3"
        set_severity_3(container=container, handle=handle)
    
    return

def set_status_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_4() called')

    phantom.set_status(container=container, status="closed")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_report_2:action_result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    create_ticket_5(container=container)

    return

def create_ticket_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_5' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report_2:action_result.parameter.threat_id', 'get_report_2:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'create_ticket_5' call
    for results_item_1 in results_data_1:
        parameters.append({
            'table': "incident",
            'fields': "",
            'vault_id': "",
            'description': formatted_data_1,
            'short_description': results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=create_ticket_5_callback, name="create_ticket_5")

    return

def create_ticket_5_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('create_ticket_5_callback() called')
    
    filter_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def get_report_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_report_2() called')

    # collect data for 'get_report_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.phishmeThreatId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_report_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'threat_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get report", parameters=parameters, assets=['phishme'], callback=format_1, name="get_report_2")

    return

def update_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_5:action_result.summary.created_ticket_id', 'create_ticket_5:action_result.parameter.table', 'create_ticket_5:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'update_ticket_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': results_item_1[1],
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=join_set_severity_3, name="update_ticket_3")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """{{\"work_notes\": \"The following source IPs connected with dst: {0}\\n\\nsrc: {1}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_ip_1:action_result.parameter.ip",
        "filtered-data:ip_filter:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    update_ticket_3(container=container)

    return

def update_ticket_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_4' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_5:action_result.summary.created_ticket_id', 'create_ticket_5:action_result.parameter.table', 'create_ticket_5:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    # build parameters list for 'update_ticket_4' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': results_item_1[1],
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=join_set_severity_3, name="update_ticket_4")

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nconnected with destination domain:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_domain_1:action_result.parameter.domain",
        "filtered-data:domain_filter:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    update_ticket_4(container=container)

    return

def format_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_4() called')
    
    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nconnected with the URL:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_url_1:action_result.parameter.url",
        "filtered-data:url_filter:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    update_ticket_5(container=container)

    return

def update_ticket_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_5' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_5:action_result.summary.created_ticket_id', 'create_ticket_5:action_result.parameter.table', 'create_ticket_5:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_4')

    parameters = []
    
    # build parameters list for 'update_ticket_5' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': results_item_1[1],
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=join_set_severity_3, name="update_ticket_5")

    return

def update_ticket_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_6() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_6' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_5:action_result.summary.created_ticket_id', 'create_ticket_5:action_result.parameter.table', 'create_ticket_5:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_5')

    parameters = []
    
    # build parameters list for 'update_ticket_6' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': results_item_1[1],
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=join_set_severity_3, name="update_ticket_6")

    return

def update_ticket_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_7() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_7' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_5:action_result.summary.created_ticket_id', 'create_ticket_5:action_result.parameter.table', 'create_ticket_5:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_6')

    parameters = []
    
    # build parameters list for 'update_ticket_7' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': results_item_1[1],
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=join_set_severity_3, name="update_ticket_7")

    return

def hunt_file_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_file_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_2:action_result.parameter.hash', 'file_reputation_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_file_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                'type': "",
                'range': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="hunt file", parameters=parameters, assets=['carbonblack'], callback=format_6, name="hunt_file_3")

    return

def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_6() called')
    
    template = """{{\"work_notes\": \"The malicious filehash {0} was found on the following hosts:\\n{1}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_file_3:action_result.parameter.hash",
        "hunt_file_3:action_result.data.*.process.results.*.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    update_ticket_7(container=container)

    return

def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_5() called')
    
    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nwere detected with the following fileHash:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_hash_3:action_result.parameter.hash",
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    update_ticket_6(container=container)

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