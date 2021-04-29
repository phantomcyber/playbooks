"""
Find AWS accounts that have not been used for a long time (90 days by default). For each unused account, gather additional group and policy information and create an artifact to enable further automation or manual action.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'calculate_start_time' block
    calculate_start_time(container=container)

    # call 'list_all_accounts' block
    list_all_accounts(container=container)

    return

"""
Calculate the time to compare against in the filter for unused accounts.
"""
def calculate_start_time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('calculate_start_time() called')
    
    literal_values_0 = [
        [
            -90,
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
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='calculate_start_time', callback=join_filter_unused_and_not_none)

    return

"""
Compare the PasswordLastUsed field to the calculated start time to find unused accounts. Ignore accounts with no value for PasswordLastUsed. This will ignore all accounts with no passwords, such as accounts that only use API access keys.
"""
def filter_unused_and_not_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_unused_and_not_none() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_all_accounts:action_result.data.*.PasswordLastUsed", "<", "calculate_start_time:custom_function_result.data.datetime_string"],
            ["list_all_accounts:action_result.data.*.PasswordLastUsed", "!=", ""],
        ],
        logical_operator='and',
        name="filter_unused_and_not_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_unused_account_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_unused_and_not_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_unused_and_not_none() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['list_all_accounts'], custom_function_names=['calculate_start_time']):
        
        # call connected block "filter_unused_and_not_none"
        filter_unused_and_not_none(container=container, handle=handle)
    
    return

"""
Create an artifact in the parent event for each unused account that was found. The CEF type will allow future automation to detect that these are AWS accounts.
"""
def save_to_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('save_to_artifacts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'save_to_artifacts' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_unused_account_info:action_result.parameter.username', 'get_unused_account_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'save_to_artifacts' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'name': "Unused AWS Account",
                'label': "user",
                'cef_name': "awsUserName",
                'contains': "aws iam user name",
                'cef_value': results_item_1[0],
                'container_id': "",
                'cef_dictionary': "",
                'run_automation': False,
                'source_data_identifier': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom'], name="save_to_artifacts", parent_action=action)

    return

"""
List all AWS IAM accounts, which will include the PasswordLastUsed field for us to filter on.
"""
def list_all_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_all_accounts() called')

    # collect data for 'list_all_accounts' call

    parameters = []
    
    # build parameters list for 'list_all_accounts' call
    parameters.append({
        'user_path': "/",
        'group_name': "",
    })

    phantom.act(action="list users", parameters=parameters, assets=['aws_iam'], callback=join_filter_unused_and_not_none, name="list_all_accounts")

    return

"""
Use the "get user" action to gather more information about the unused accounts, including group membership and policy assignments.
"""
def get_unused_account_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_unused_account_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_unused_account_info' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_unused_and_not_none:condition_1:list_all_accounts:action_result.data.*.UserName", "filtered-data:filter_unused_and_not_none:condition_1:list_all_accounts:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'get_unused_account_info' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'username': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="get user", parameters=parameters, assets=['aws_iam'], callback=save_to_artifacts, name="get_unused_account_info")

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