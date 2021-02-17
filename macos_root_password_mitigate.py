"""
Responds to CVE-2017-13872 by using SSH to access MacOS endpoints. First the following information is gathered: MacOS version number, whether TCP port 5900 is open, whether the root account is enabled, and when the root account password was last changed. The gathered information is then compiled into an email and Zendesk ticket for analysis. Then through a prompt an analyst can decide whether to disable the ARD remote screen sharing service and/or add a long, random password for the root account.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import os
import base64
import re
import pprint

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'open_event_status' block
    open_event_status(container=container)

    return

"""
Set this event to "Open".
"""
def open_event_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('open_event_status() called')

    phantom.set_status(container=container, status="open")
    ssh_detect_high_sierra(container=container)

    return

"""
Use the sw_vers command to check the MacOS version.
"""
def ssh_detect_high_sierra(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('execute_program_3() called')
    
    success, message, macos_endpoints = phantom.get_list("macos_endpoints")
    phantom.debug("using the following ip addresses from the custom list:")
    phantom.debug(macos_endpoints)

    parameters = []
    
    # build parameters list for 'execute_program_1' call
    for macos_endpoint in macos_endpoints:
        parameters.append({
            'ip_hostname': macos_endpoint[0],
            'command': "sw_vers",
            'timeout': "",
    })

    phantom.act("execute program", parameters=parameters, assets=['ssh_macos_administrator'], callback=filter_1, name="ssh_detect_high_sierra")    
    
    return

"""
Only proceed with MacOS High Sierra endpoints. High Sierra is 10.13.x
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ProductVersion:	10.13", "in", "ssh_detect_high_sierra:action_result.data.*.output"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        nmap_scan_5900(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        ssh_parse_user_plist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        ssh_raw_user_plist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Use nmap to syn-ack scan against TCP port 5900, which is the default for Apple Remote Desktop (ARD) and VNC.
"""
def nmap_scan_5900(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('nmap_scan_5900() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'nmap_scan_5900' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'nmap_scan_5900' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'script': "",
                'portlist': 5900,
                'udp_scan': "",
                'ip_hostname': filtered_results_item_1[0],
                'script-args': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="scan network", parameters=parameters, assets=['nmap'], callback=join_format_email_and_ticket, name="nmap_scan_5900")

    return

"""
Parse the dslocal plist to determine whether the root user is enabled. The password will show as ******** if the root user is enabled, otherwise it will be *
"""
def ssh_parse_user_plist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_parse_user_plist() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_parse_user_plist' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'ssh_parse_user_plist' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': "sudo plutil -p /private/var/db/dslocal/nodes/Default/users/root.plist | grep -A 1 \\\"passwd\\\"",
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], callback=join_format_email_and_ticket, name="ssh_parse_user_plist")

    return

"""
Pull the raw plist because the passwordLastSetTime will not be parsed with the plutil command. Grep is used to convert the binary output into ascii.
"""
def ssh_raw_user_plist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_raw_user_plist() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_raw_user_plist' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'ssh_raw_user_plist' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': "sudo cat /private/var/db/dslocal/nodes/Default/users/root.plist | grep --text -A 1 passwordLastSetTime",
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], callback=join_format_email_and_ticket, name="ssh_raw_user_plist")

    return

"""
Contact an administrator or analyst with all the gathered information.
"""
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email_and_ticket')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'cc': "",
        'to': "admin@contoso.corp",
        'bcc': "",
        'body': formatted_data_1,
        'from': "",
        'headers': "",
        'subject': "Phantom Automation - MacOS High Sierra Root Password Mitigation",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=macos_high_sierra_disable_ard, name="send_email_1")

    return

"""
Create a Zendesk ticket with all the gathered information.
"""
def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email_and_ticket')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'fields': "",
        'subject': "MacOS High Sierra Root Password Mitigation",
        'description': formatted_data_1,
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['zendesk'], callback=macos_high_sierra_set_root_password, name="create_ticket_1")

    return

"""
Proceed if the analyst responds Yes.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["macos_high_sierra_disable_ard:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ssh_disable_ARD(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Proceed if the analyst responds Yes.
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["macos_high_sierra_set_root_password:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_osascript(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Ask an analyst whether to disable ARD on the detected endpoints.
"""
def macos_high_sierra_disable_ard(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('macos_high_sierra_disable_ard() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Would you like to disable ARD on the detected vulnerable MacOS High Sierra endpoints?
 
Consider the evidence in container {0} and make a determination on whether or not to disable Apple Remote Desktop on the detected MacOS High Sierra endpoints, which are vulnerable to root account login with a blank password.

Choose \"Yes\" to disable ARD (a remote screen sharing service like VNC or RDP) on the endpoints with the following IP addresses:
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="macos_high_sierra_disable_ard", parameters=parameters, response_types=response_types, callback=decision_1)

    return

"""
Ask an analyst whether to set the root password to a 40-character random string generated with the Phantom server's operating system's urandom and base64-encoded.
"""
def macos_high_sierra_set_root_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('macos_high_sierra_set_root_password() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Would you like to set a random root password on the detected vulnerable MacOS High Sierra endpoints?
 
Consider the evidence in container {0} and make a determination on whether or not to set the same 40-character random root password on the detected endpoints, which are vulnerable to root account login with a blank password.

Choose \"Yes\" to set the root password on the endpoints with the following IP addresses:
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="macos_high_sierra_set_root_password", parameters=parameters, response_types=response_types, callback=decision_2)

    return

"""
The first two tries of this command enable the root user and set the password. These should fail.
"""
def ssh_try_root_once(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_try_root_once() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_try_root_once' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])
    formatted_data_1 = phantom.get_format_data(name='format_osascript')

    parameters = []
    
    # build parameters list for 'ssh_try_root_once' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': formatted_data_1,
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], callback=ssh_try_root_twice, name="ssh_try_root_once")

    return

"""
The first two tries of this command enable the root user and set the password. These should fail.
"""
def ssh_try_root_twice(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_try_root_twice() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_try_root_twice' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])
    formatted_data_1 = phantom.get_format_data(name='format_osascript')

    parameters = []
    
    # build parameters list for 'ssh_try_root_twice' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': formatted_data_1,
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], callback=ssh_try_root_thrice, name="ssh_try_root_twice", parent_action=action)

    return

"""
The third try should succeed and just return a UID of 0.
"""
def ssh_try_root_thrice(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_try_root_thrice() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_try_root_thrice' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])
    formatted_data_1 = phantom.get_format_data(name='format_osascript')

    parameters = []
    
    # build parameters list for 'ssh_try_root_thrice' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': formatted_data_1,
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], name="ssh_try_root_thrice", parent_action=action)

    return

"""
Use the built-in perl script called "kickstart" to turn off all access to ARD, stopping the service listening on TCP 5900.
"""
def ssh_disable_ARD(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ssh_disable_ARD() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ssh_disable_ARD' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname", "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'ssh_disable_ARD' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'command': "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off",
                'timeout': "",
                'ip_hostname': filtered_results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh_macos_administrator'], name="ssh_disable_ARD")

    return

"""
Compile the gathered information into a message used for both email and ticket creation.
"""
def format_email_and_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email_and_ticket() called')
    
    high_sierra_ip_addrs = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname'], action_results=results)
    nmap_results = phantom.collect2(container=container, datapath=['nmap_scan_5900:action_result.data.*.tcp.*.state'], action_results=results)
    parse_plist_results = phantom.collect2(container=container, datapath=['ssh_parse_user_plist:action_result.data.*.output'], action_results=results)
    raw_plist_results = phantom.collect2(container=container, datapath=['ssh_raw_user_plist:action_result.data.*.output'], action_results=results)
    
    phantom.debug("high_sierra_ip_addrs")
    phantom.debug(high_sierra_ip_addrs)
    phantom.debug("nmap_results:")
    phantom.debug(nmap_results)
    phantom.debug("parse_plist_results:")
    phantom.debug(parse_plist_results)
    phantom.debug("raw_plist_results:")
    phantom.debug(raw_plist_results)
    
    result_summaries = []
    for idx, val in enumerate(high_sierra_ip_addrs):
        result_summary = {'ip_addr': val[0]}
        result_summary['is_port_5900_open?'] = (nmap_results[idx][0] == 'open')
        result_summary['is_root_pass_set?'] = ('***' in parse_plist_results[idx][0])
        result_summary['last_root_pass_set_time'] = re.search('<real>(.*)</real>', raw_plist_results[idx][0]).group(1)
        result_summaries.append(result_summary)
    
    phantom.debug(result_summaries)
    
    template = """Phantom has detected the following endpoints running MacOS High Sierra:
{0}

At 1:38pm EST on 2017-11-28 it was publicly announced that in High Sierra the root user account can be enabled by trying to authenticate with any password. This is remotely exploitable if Apple Remote Desktop is enabled and listening on port 5900.

Here is the current state of each of the identified High Sierra endpoints:

""" + pprint.pformat(result_summaries).replace('{', '[').replace('}', ']') + """

Multiple different configurations can be vulnerable in different ways. If the root password is not set and the endpoint is listening on port 5900, the endpoint can be trivially exploited from a remote adversary using an ARD client. If port 5900 is not open the endpoint is only vulnerable to physical access. If the root password is set the time should be taken into account, and an investigation should be done to determine whether or not that was done by an adversary.

To see additional context, respond to prompts, and run additional response actions use Mission Control within Phantom to access the Event with ID {1}

Apple Security Update 2017-001 has been released to fix this vulnerability and should be installed as soon as possible."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:ssh_detect_high_sierra:action_result.parameter.ip_hostname",
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_and_ticket")

    send_email_1(container=container)
    create_ticket_1(container=container)

    return

def join_format_email_and_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_email_and_ticket() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['nmap_scan_5900', 'ssh_parse_user_plist', 'ssh_raw_user_plist']):
        
        # call connected block "format_email_and_ticket"
        format_email_and_ticket(container=container, handle=handle)
    
    return

"""
Prepare the SSH command to use osascript with a new root password.
"""
def format_osascript(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_osascript() called')
    
    new_root_password = base64.b64encode(os.urandom(30))
    
    template = """osascript -e 'do shell script \"id\" with administrator privileges user name \"root\" password \"""" + new_root_password + """\"'"""

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=template, parameters=parameters, name="format_osascript")

    ssh_try_root_once(container=container)

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