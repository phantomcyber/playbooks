"""
Execute proactive patching against Windows endpoints associated with a WannaCry event.  Endpoints that require patching are forced to update and are added to the custom list wannacry_patched_endpoints custom list.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

def add_endpoint_to_patched_list(container):
        # collect data for 'add_to_remediated_list_1' call
    infected_endpoints = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    
    phantom_url = phantom.get_base_url()
    container_url = "{}/mission/{}".format(phantom_url, container['id'])
    
    for infected_endpoint in infected_endpoints:
        if infected_endpoint[0]:
            phantom.datastore_add('wannacry_patched_endpoints', [ infected_endpoint[0], 'yes',  container_url ] )
            
    return

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Windows", "in", "list_endpoints_1:action_result.data.*.os_environment_display_string"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hotfix_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket_description')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Forced updates for wannacry prevention",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=execute_win_update, name="create_ticket_1")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["KB4012598", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012212", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012215", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012213", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012216", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
        ],
        logical_operator='and',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ticket_description(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def hotfix_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hotfix_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hotfix_query' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:list_endpoints_1:action_result.data.*.ips", "filtered-data:filter_1:condition_1:list_endpoints_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'hotfix_query' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'query': "select * from win32_quickfixengineering",
                'namespace': "",
                'ip_hostname': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="run query", parameters=parameters, assets=['domainctrl1'], callback=filter_4, name="hotfix_query")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:wannacry_patched_endpoints"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        list_endpoints_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def list_endpoints_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_endpoints_1() called')

    parameters = []

    phantom.act(action="list endpoints", parameters=parameters, assets=['carbonblack'], callback=filter_1, name="list_endpoints_1")

    return

def validate_hotfix(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('validate_hotfix() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'validate_hotfix' call
    results_data_1 = phantom.collect2(container=container, datapath=['execute_win_update:action_result.parameter.ip_hostname', 'execute_win_update:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'validate_hotfix' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'query': "select * from win32_quickfixengineering",
                'namespace': "",
                'ip_hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="run query", parameters=parameters, assets=['domainctrl1'], callback=filter_5, name="validate_hotfix", parent_action=action)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["KB4012598", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012212", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012215", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012213", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
            ["KB4012216", "not in", "hotfix_query:action_result.data.*.*.HotFixID"],
        ],
        logical_operator='and',
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ticket_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update the ticket with the list of endpoints that were not patched and still require remediation.
"""
def update_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_ticket_comment')

    parameters = []
    
    # build parameters list for 'update_ticket_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'table': "incident",
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], name="update_ticket_2")

    return

def execute_win_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('execute_win_update() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'execute_win_update' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:hotfix_query:action_result.parameter.ip_hostname", "filtered-data:filter_4:condition_1:hotfix_query:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'execute_win_update' call
    for filtered_results_item_1 in filtered_results_data_1:
        parameters.append({
            'ph': "",
            'args': "",
            'program': "wauclt.exe /updatenow",
            'ip_hostname': filtered_results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_results_item_1[1]},
        })

    phantom.act(action="execute program", parameters=parameters, assets=['domainctrl1'], callback=validate_hotfix, name="execute_win_update", parent_action=action)

    return

"""
Format return information in preparation for ticketing.
"""
def format_ticket_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_comment() called')
    
    template = """{{\"work_notes\": \"The following systems did not successfully update from the required hotfix:
{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_5:condition_1:hotfix_query:action_result.parameter.ip_hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_comment")

    update_ticket_2(container=container)

    return

"""
List the affected hosts in the ticket description.
"""
def format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_description() called')
    
    template = """The following endpoints on the network are running windows and will require an immediate update to receive a patch protecting against the wannacry outbreak: 
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:hotfix_query:action_result.parameter.ip_hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_description")

    create_ticket_1(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    
    add_endpoint_to_patched_list(container)
    
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