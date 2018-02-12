"""
This Playbook enables automatic response to notifications from a Nagios server that is monitoring Linux services. When Nagios detects service disruption it is configured to send an email to Phantom, which will trigger this Playbook to attempt a quick fix for the issue by using SSH to restart the System V service in question. The target hostname/IP and service name are parsed from the subject line of the email from Nagios then each parameter is checked against a whitelist (a Custom List on Phantom) before sending the SSH command.

Community Contributor: Lora Fulton
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
Only process emails with subject lines matching the Nagios subject format for service notifications.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["PROBLEM Service Alert:", "in", "artifact:*.cef.emailHeaders.Subject"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Build the "service restart" SSH command with the parsed target hostname or IP and the parsed service name.
"""
def execute_program_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('execute_program_1() called')

    # collect data for 'execute_program_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')
    formatted_data_2 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'execute_program_1' call
    parameters.append({
        'ip_hostname': formatted_data_1,
        'command': formatted_data_2,
        'timeout': "",
    })

    if parameters[0]["ip_hostname"] == "hostname whitelist check failed":
        return
    if parameters[0]["command"] == "service name whitelist check failed":
        return

    phantom.act("execute program", parameters=parameters, assets=['ssh'], name="execute_program_1")    
    
    return

def join_execute_program_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_execute_program_1() called')

    # no callbacks to check, call connected block "execute_program_1"
    phantom.save_run_data(key='join_execute_program_1_called', value='execute_program_1', auto=True)

    execute_program_1(container=container, handle=handle)
    
    return

"""
Parse the hostname or IP address of the SSH target server and check it against a whitelist (a Custom List).
"""
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    container_data = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject'])
    
    command = ""
    for result in container_data:
        if result[0] and "Service Alert" in result[0]:
            parts = result[0].split("** PROBLEM Service Alert: ")
            hostname_ip = parts[1].split('/')[0]

    success, message, whitelist = phantom.get_list("nagios_service_monitoring_hostname_ip_whitelist")
    if [hostname_ip] in whitelist:
        phantom.debug("hostname whitelist check passed")
    else:
        phantom.error("hostname whitelist check failed")
        phantom.comment(container=container, comment="hostname whitelist check failed")
        hostname_ip = "hostname whitelist check failed"

    phantom.format(container=container, template=hostname_ip, parameters=[""], name="format_1")

    #join_execute_program_1(container=container)

    return

"""
Parse the service name reported by Nagios and check it against a whitelist (a Custom List).
"""
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')

    container_data = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Subject'])
    
    service = ""
    for result in container_data:
        if result[0] and "Service Alert" in result[0]:
            parts = result[0].split("** PROBLEM Service Alert: ")
            service = parts[1].split('/')[1].split(" process is CRITICAL")[0]

    ssh_command = "service {} restart".format(service)
    
    success, message, whitelist = phantom.get_list("nagios_service_monitoring_service_name_whitelist")
    if [service] in whitelist:
        phantom.debug("service name whitelist check passed")
    else:
        phantom.error("service name whitelist check failed")
        phantom.comment(container=container, comment="service name whitelist check failed")
        ssh_command = "service name whitelist check failed"

    phantom.format(container=container, template=ssh_command, parameters=[""], name="format_2")

    join_execute_program_1(container=container)

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