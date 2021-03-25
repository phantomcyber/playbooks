"""
Conduct a census of all the new users added to Azure Active Directory in the last week. Query both the Azure AD Graph API and the Office 365 Graph API to identify user accounts that can be managed in both.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'list_users_azure_ad' block
    list_users_azure_ad(container=container)

    # call 'cf_community_datetime_modify_1' block
    cf_community_datetime_modify_1(container=container)

    return

"""
List all users in Azure AD
"""
def list_users_azure_ad(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_users_azure_ad() called')

    # collect data for 'list_users_azure_ad' call

    parameters = []
    
    # build parameters list for 'list_users_azure_ad' call
    parameters.append({
        'filter_string': "",
    })

    phantom.act(action="list users", parameters=parameters, assets=['azure_ad_graph'], callback=join_new_user_filter, name="list_users_azure_ad")

    return

"""
Create a time stamp to compare against for finding new users. Change the amount_to_modify to adjust the number of days to look back.
"""
def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    literal_values_0 = [
        [
            -7,
            "days",
            "%Y-%m-%dT%H:%M:%SZ",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        parameters.append({
            'input_datetime': None,
            'amount_to_modify': item0[0],
            'modification_unit': item0[1],
            'input_format_string': None,
            'output_format_string': item0[2],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_1', callback=join_new_user_filter)

    return

"""
Filter on users created recently using the createdDateTime field
"""
def new_user_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('new_user_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_users_azure_ad:action_result.data.*.createdDateTime", ">=", "cf_community_datetime_modify_1:custom_function_result.data.datetime_string"],
        ],
        name="new_user_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_graph_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_new_user_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_new_user_filter() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['list_users_azure_ad'], custom_function_names=['cf_community_datetime_modify_1']):
        
        # call connected block "new_user_filter"
        new_user_filter(container=container, handle=handle)
    
    return

"""
Format a $filter for Microsoft Graph to match the userPrincipalName
"""
def format_graph_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_graph_filter() called')
    
    template = """%%
userPrincipalName eq '{0}'
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:new_user_filter:condition_1:list_users_azure_ad:action_result.data.*.userPrincipalName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_graph_filter")

    list_users_ms_graph(container=container)

    return

"""
Identify the corresponding user in the Microsoft Graph
"""
def list_users_ms_graph(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_users_ms_graph() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_users_ms_graph' call
    formatted_data_1 = phantom.get_format_data(name='format_graph_filter__as_list')

    parameters = []
    
    # build parameters list for 'list_users_ms_graph' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'limit': "",
            'filter': formatted_part_1,
        })

    phantom.act(action="list users", parameters=parameters, assets=['ms_graph_o365'], callback=match_users, name="list_users_ms_graph")

    return

"""
Match the userPrincipalName fields from the Azure AD API and the MS Graph API to collect matching records from both
"""
def match_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('match_users() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_users_ms_graph:action_result.data.*.userPrincipalName", "==", "list_users_azure_ad:action_result.data.*.userPrincipalName"],
        ],
        name="match_users:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        save_user_artifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Gather the most important fields to present in a note
"""
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_note() called')
    
    template = """New users:

%%
| userPrincipalName | {0} |
|---|---|
| displayName | {1} |
| mail | {2} |
| jobTitle | {3} |
| officeLocation | {4} |
| id | {5}
| createdDateTime | {6} |
---
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.userPrincipalName",
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.displayName",
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.mail",
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.jobTitle",
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.officeLocation",
        "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.id",
        "filtered-data:match_users:condition_1:list_users_azure_ad:action_result.data.*.createdDateTime",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    add_note_3(container=container)

    return

"""
Post the note to the investigation
"""
def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='format_note')

    note_title = "Azure New User Census"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Save the userPrincipalName of each user as an artifact to allow further investigation and remediation
"""
def save_user_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('save_user_artifacts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'save_user_artifacts' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.userPrincipalName", "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.data.*.id", "filtered-data:match_users:condition_1:list_users_ms_graph:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'save_user_artifacts' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[1]:
            parameters.append({
                'name': "New Azure User",
                'label': "user",
                'cef_name': "userPrincipalName",
                'contains': "azure user principal name",
                'cef_value': filtered_results_item_1[0],
                'container_id': id_value,
                'cef_dictionary': "",
                'run_automation': False,
                'source_data_identifier': filtered_results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[2]},
            })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom'], name="save_user_artifacts")

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