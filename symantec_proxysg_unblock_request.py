"""
This playbook is designed to facilitate a Website Unblock type of request from a ticketing system.  It is designed to operate on containers that are ingested from a ticketing platform such as JIRA or ServiceNow that contain the website URL requested as well as the requesting user.  The playbook performs some 3rd party reputation lookups as well as a BlueCoat WebPulse categorization request.  Appropriate notifications are sent to users and the original request ticket is updated at the end based on the outcome.

Warning: The "detonate url" action on urlscan.io will make the submitted URL visible to anyone on the Internet through the public urlscan.io site.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block


def collectAll(container=None, datapath=None):
    return phantom.collect2(container=container, scope='all', datapath=datapath)

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_2' block
    filter_2(container=container)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fromEmail", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        virustotal_url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def virustotal_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('virustotal_url_reputation() called')

    # collect data for 'virustotal_url_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'virustotal_url_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=format_deny_email, name="virustotal_url_reputation")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        allow_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "No"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        send_deny_email_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """A user is requesting to unblock the website at URL: 
{0}

Reputation services have not indicated that this site is malicious.  Additional information is contained in Mission Control.  Do you want to allow this?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.requestURL",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'size': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshot machine'], callback=detonate_url_1, name="get_screenshot_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["virustotal_url_reputation:action_result.summary.positives", "==", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        webpulse_url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_send_deny_email_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def webpulse_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('webpulse_url_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'webpulse_url_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'webpulse_url_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['blue_coat'], callback=decision_3, name="webpulse_url_reputation")

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Malicious", "in", "webpulse_url_reputation:action_result.data.*.categories"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_send_deny_email_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Malware", "in", "webpulse_url_reputation:action_result.data.*.categories"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        join_send_deny_email_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    get_screenshot_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonate_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'private': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="detonate url", parameters=parameters, assets=['urlscan'], callback=prompt_1, name="detonate_url_1", parent_action=action)

    return

def allow_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('allow_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'allow_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'allow_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="allow url", parameters=parameters, assets=['blue_coat'], callback=send_approve_email, name="allow_url_1")

    return

def send_deny_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_deny_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_deny_email_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_deny_email')

    parameters = []
    
    # build parameters list for 'send_deny_email_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'cc': "",
                'to': filtered_artifacts_item_1[0],
                'bcc': "",
                'body': formatted_data_1,
                'from': "phantom-notifications@company.com",
                'headers': "",
                'subject': "Request Denied",
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=join_update_ticket_denied, name="send_deny_email_2")

    return

def join_send_deny_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_send_deny_email_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_send_deny_email_2_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['virustotal_url_reputation', 'webpulse_url_reputation']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_send_deny_email_2_called', value='send_deny_email_2')
        
        # call connected block "send_deny_email_2"
        send_deny_email_2(container=container, handle=handle)
    
    return

def send_deny_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_deny_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_deny_email_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'send_deny_email_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'cc': "",
                'to': filtered_artifacts_item_1[0],
                'bcc': "",
                'body': "Your request has been denied by an approver. ",
                'from': "phantom-notifications@company.com",
                'headers': "",
                'subject': "Request Denied",
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=join_update_ticket_denied, name="send_deny_email_1")

    return

def send_approve_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_approve_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_approve_email' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'send_approve_email' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'cc': "",
                'to': filtered_artifacts_item_1[0],
                'bcc': "",
                'body': "Your request to unblock a website has been approved. ",
                'from': "phantom-notifications@company.com",
                'headers': "",
                'subject': "Request Approved",
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=update_ticket_approved, name="send_approve_email", parent_action=action)

    return

def update_ticket_approved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_approved() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'update_ticket_approved' call

    parameters = []
    
    # build parameters list for 'update_ticket_approved' call
    parameters.append({
        'id': name_value,
        'vault_id': "",
        'update_fields': "{\"update\": {\"comment\": [{\"add\": {\"body\": \"Request Approved\"}}]}}",
    })

    phantom.act(action="update ticket", parameters=parameters, assets=['jira'], name="update_ticket_approved", parent_action=action)

    return

def update_ticket_denied(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_denied() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'update_ticket_denied' call

    parameters = []
    
    # build parameters list for 'update_ticket_denied' call
    parameters.append({
        'id': name_value,
        'vault_id': "",
        'update_fields': "{\"update\": {\"comment\": [{\"add\": {\"body\": \"Request Denied\"}}]}}",
    })

    phantom.act(action="update ticket", parameters=parameters, assets=['jira'], name="update_ticket_denied")

    return

def join_update_ticket_denied(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_update_ticket_denied() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_ticket_denied_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['send_deny_email_2', 'send_deny_email_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_update_ticket_denied_called', value='update_ticket_denied')
        
        # call connected block "update_ticket_denied"
        update_ticket_denied(container=container, handle=handle)
    
    return

def format_deny_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_deny_email() called')
    
    template = """Your request to unblock a website has been denied.

The website at: 
{0}

has been determined to be malicious by {1} different 3rd party reputation services."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.requestURL",
        "virustotal_url_reputation:action_result.summary.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_deny_email")

    decision_1(container=container)

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