"""
Process a detection created by Vectra and send the relevant information in a notification email.

Author: Chris Johnson
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.act", "==", "block"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        get_detections_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

"""
Query for matching detections to retrieve the type.
"""
def get_detections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_detections_1() called')

    # collect data for 'get_detections_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dvc', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_detections_1' call
    for container_item in container_data:
        parameters.append({
            'src_ip': container_item[0],
            'state': "active",
            'dettypes': "Suspicious Remote Execution",
            'dest_port': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act("get detections", parameters=parameters, assets=['vae-demo'], callback=format_email, name="get_detections_1")

    return

"""
Build the email body for the notification.
"""
def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_email() called')
    
    template = """This is a notification that the following host has exceeded the threshold and needs further investigation:

Hostname:
{0} 

IP:
{1} 

Detections:
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.dvchost",
        "artifact:*.cef.dvc",
        "get_detections_1:action_result.data.*.*.type",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    send_email_1(container=container)

    return

"""
Send the email.
"""
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'to': "soc_team@example.com",
        'from': "phantom@example.com",
        'attachments': "",
        'subject': "Notification from Vectra via Phantom",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

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