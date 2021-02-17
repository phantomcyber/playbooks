"""
This playbook responds automatically when a threat intelligence service detects that one or more of our internal email addresses have been compromised and are sending malicious outbound email. First we will run a query to find the LDAP accounts associated with the identified email addresses. Then if the Phantom admin approves, those LDAP accounts will have their passwords reset to prevent further misuse. All investigation results and actions taken will be documented as "Work notes" in a newly created ServiceNow ticket.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

"""
Query LDAP for the user account with the given email address.
"""
def query_ldap(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_ldap() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_ldap' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'query_ldap' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'fields': "",
                'username': filtered_artifacts_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['ldap'], callback=filter_2, name="query_ldap", parent_action=action)

    return

"""
Split based on whether or not the given email address is associated with an LDAP account.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["query_ldap:action_result.data.*.samaccountname", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ticket_fields(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["query_ldap:action_result.data.*.samaccountname", "==", ""],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        missing_users(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Prompt the admin user before resetting passwords because it could affect operations.
"""
def compromised_email_password_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('compromised_email_password_reset() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """A threat intelligence service has detected that one or more of our internal email accounts has been compromised and is being used to send malicious outbound email. The following email addresses have been identified and found to be associated with LDAP accounts:
{0}

Select Yes to reset the passwords on the associated LDAP accounts."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:query_ldap:action_result.parameter.username",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="compromised_email_password_reset", parameters=parameters, response_types=response_types, callback=decision_1)

    return

"""
Split on whether or not the admin approved the password resets.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["compromised_email_password_reset:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        reset_password_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    reset_denied(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Use LDAP to reset passwords on the identified accounts. This will require users to login manually to choose new passwords.
"""
def reset_password_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reset_password_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:query_ldap:action_result.parameter.username", "filtered-data:filter_2:condition_1:query_ldap:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'reset_password_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'username': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="reset password", parameters=parameters, assets=['ldap'], callback=decision_2, name="reset_password_2")

    return

"""
Split on whether or not the password resets succeeded.
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["reset_password_2:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        reset_succeeded(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    reset_failed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Enrich the ticket with the list of accounts that were successfully reset.
"""
def update_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='reset_succeeded')

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

"""
Enrich the ticket with the list of accounts where password reset failed and show the error message.
"""
def update_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='reset_failed')

    parameters = []
    
    # build parameters list for 'update_ticket_3' call
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

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], name="update_ticket_3")

    return

"""
Enrich the ticket with the list of accounts for which the Phantom admin denied the password reset.
"""
def update_ticket_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_4' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='reset_denied')

    parameters = []
    
    # build parameters list for 'update_ticket_4' call
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

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], name="update_ticket_4")

    return

"""
Only process artifacts with internal email addresses.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["@corp.contoso.com", "in", "artifact:*.cef.fromEmail"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ticket_description(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
This uses the default ServiceNow ticket type: "Incident". The returned ticket ID will be used to update this ticket once more is known.
"""
def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')

    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket_description')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "compromised internal email account",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=query_ldap, name="create_ticket_1")

    return

"""
Enrich the ticket with list of email addresses that are associated with LDAP accounts.
"""
def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_ticket_fields')

    parameters = []
    
    # build parameters list for 'update_ticket_1' call
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

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], callback=compromised_email_password_reset, name="update_ticket_1")

    return

"""
Enrich the ticket with the list of email addresses that are not associated with LDAP accounts and explain why that might be.
"""
def update_ticket_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_5' call
    results_data_1 = phantom.collect2(container=container, datapath=['create_ticket_1:action_result.summary.created_ticket_id', 'create_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='missing_users')

    parameters = []
    
    # build parameters list for 'update_ticket_5' call
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

    phantom.act(action="update ticket", parameters=parameters, assets=['servicenow'], name="update_ticket_5")

    return

"""
Start the ticket with the list of email addresses and an overview of what the playbook is going to do.
"""
def format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_description() called')
    
    template = """A threat intelligence service has detected that one or more of our internal email accounts has been compromised and is being used to send malicious outbound email. The following email addresses have been identified:
{0}

Now Phantom will run a query to find the LDAP accounts associated with the identified email addresses. Then if the Phantom admin approves, those LDAP accounts will have their passwords reset to prevent further misuse. All investigation results and containment actions taken will be documented as \"Work notes\" in this ticket."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_description")

    create_ticket_1(container=container)

    return

"""
Enrich the ticket with list of email addresses that are associated with LDAP accounts.
"""
def format_ticket_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_fields() called')
    
    template = """{{ \"work_notes\": \"Found LDAP Users: Phantom automatically ran an LDAP query and LDAP users were found with the following email addresses:\\n{0}\\n\\nNext the Phantom admin will be prompted about whether or not to reset those user's passwords.\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:query_ldap:action_result.parameter.username",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_fields")

    update_ticket_1(container=container)

    return

"""
Enrich the ticket with the list of accounts that were successfully reset.
"""
def reset_succeeded(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_succeeded() called')
    
    template = """{{ \"work_notes\": \"LDAP Password Reset Succeeded: The Phantom admin accepted the prompt and LDAP passwords were automatically reset for the following email accounts:\\n{0}\\n\\nNo further automated action will be taken by Phantom at this time.\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "reset_password_2:action_result.parameter.username",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reset_succeeded")

    update_ticket_2(container=container)

    return

"""
Enrich the ticket with the list of accounts where password reset failed and show the error message.
"""
def reset_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_failed() called')
    
    template = """{{ \"work_notes\": \"LDAP Password Reset Failed: The Phantom admin accepted the prompt but the LDAP password reset failed for the following email accounts:\\n{0}\\n\\nThe failure message was:\\n{1}\\n\\nNo further automated action will be taken by Phantom at this time.\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "reset_password_2:action_result.parameter.username",
        "reset_password_2:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reset_failed")

    update_ticket_3(container=container)

    return

"""
Enrich the ticket with the list of accounts for which the Phantom admin denied the password reset.
"""
def reset_denied(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_denied() called')
    
    template = """{{ \"work_notes\": \"Admin Denied Password Reset: The Phantom admin denied the prompt asking whether or not LDAP passwords should be automatically reset for the following email accounts:\\n{0}\\n\\nNo further automated action will be taken by Phantom at this time, but this should be investigated further.\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:query_ldap:action_result.parameter.username",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reset_denied")

    update_ticket_4(container=container)

    return

"""
Enrich the ticket with the list of email addresses that are not associated with LDAP accounts and explain why that might be.
"""
def missing_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_users() called')
    
    template = """{{ \"work_notes\": \"Missing LDAP Users: Phantom automatically ran an LDAP query and no LDAP users were found with the following email addresses:\\n{0}\\n\\nThe threat intelligence alert may have been a false positive or an adversary may be spoofing a non-existent company email address. No further automated action will be taken by Phantom at this time, but this should be investigated further.\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:query_ldap:action_result.parameter.username",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="missing_users")

    update_ticket_5(container=container)

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