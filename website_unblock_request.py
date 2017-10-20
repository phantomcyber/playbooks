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

def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_ticket_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'update_ticket_1' call

    parameters = []
    
    # build parameters list for 'update_ticket_1' call
    parameters.append({
        'update_fields': "{\"update\": {\"comment\": [{\"add\": {\"body\": \"Request Denied\"}}]}}",
        'vault_id': "",
        'id': name_value,
    })

    phantom.act("update ticket", parameters=parameters, assets=['jira'], name="update_ticket_1")    
    
    return

def join_update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_update_ticket_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_ticket_1_called'):
        return

    # no callbacks to check, call connected block "update_ticket_1"
    phantom.save_run_data(key='join_update_ticket_1_called', value='update_ticket_1', auto=True)

    update_ticket_1(container=container, handle=handle)
    
    return

def update_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_ticket_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'update_ticket_2' call

    parameters = []
    
    # build parameters list for 'update_ticket_2' call
    parameters.append({
        'update_fields': "{\"update\": {\"comment\": [{\"add\": {\"body\": \"Request Approved\"}}]}}",
        'vault_id': "",
        'id': name_value,
    })

    phantom.act("update ticket", parameters=parameters, assets=['jira'], name="update_ticket_2", parent_action=action)    
    
    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Your request to unblock a website has been denied.

The website at: 
{0}

has been determined to be malicious by {1} different 3rd party reputation services."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.requestURL",
        "url_reputation_1:action_result.summary.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    decision_1(container=container)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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
        filter_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'url': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("url reputation", parameters=parameters, assets=['virustotal'], callback=format_1, name="url_reputation_1")    
    
    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", "==", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        BlueCoat_WebPulse(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def BlueCoat_WebPulse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('BlueCoat_WebPulse() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'BlueCoat_WebPulse' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'BlueCoat_WebPulse' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'url': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("url reputation", parameters=parameters, assets=['blue_coat'], callback=decision_3, name="BlueCoat_WebPulse")    
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Malicious", "in", "BlueCoat_WebPulse:action_result.data.*.categories"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Malware", "in", "BlueCoat_WebPulse:action_result.data.*.categories"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 3
    get_screenshot_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, options=options, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        allow_url_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "No"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        send_email_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'send_email_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'body': "Your request has been denied by an approver. ",
            'to': filtered_artifacts_item_1[0],
            'from': "phantom-notifications@company.com",
            'attachments': "",
            'subject': "Request Denied",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=join_update_ticket_1, name="send_email_2")    
    
    return

def send_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_3' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'send_email_3' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'body': "Your request to unblock a website has been approved. ",
            'to': filtered_artifacts_item_1[0],
            'from': "phantom-notifications@company.com",
            'attachments': "",
            'subject': "Request Approved",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=update_ticket_2, name="send_email_3", parent_action=action)    
    
    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filter_2:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'body': formatted_data_1,
            'to': filtered_artifacts_item_1[0],
            'from': "phantom-notifications@company.com",
            'attachments': "",
            'subject': "Request Denied",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=join_update_ticket_1, name="send_email_1")    
    
    return

def join_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_send_email_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_send_email_1_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'url_reputation_1' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_send_email_1_called', value='send_email_1')
        
        # call connected block "send_email_1"
        send_email_1(container=container, handle=handle)
    
    return

def allow_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('allow_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'allow_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'allow_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'url': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("allow url", parameters=parameters, assets=['blue_coat'], callback=send_email_3, name="allow_url_1")    
    
    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_screenshot_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'url': filtered_artifacts_item_1[0],
            'size': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act("get screenshot", parameters=parameters, assets=['screenshot machine'], callback=detonate_url_1, name="get_screenshot_1")    
    
    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    phantom.act("detonate url", parameters=parameters, assets=['urlscan_io'], callback=prompt_1, name="detonate_url_1", parent_action=action)    
    
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