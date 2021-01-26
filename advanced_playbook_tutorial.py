"""
This example Playbook was created for a tutorial to show various features of the Phantom playbook editor, including filters, decisions, custom lists, prompts and scheduled actions.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

"""
Start the investigation by checking if there is any threat intelligence about the file hash in the event.
"""
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['reversinglabs'], callback=filter_1, name="file_reputation_1")

    return

"""
Check if more than 10 intelligence sources identify the file as malicious.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 10],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Reference the file that was found to be malicious in the previous filter.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:file_reputation_1:action_result.parameter.hash", "==", "artifact:*.cef.fileHash"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        terminate_process_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if the machine hostname is on a list used to track test machines.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:test_machines"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Raise the severity of the event if the machine is not a test machine.
"""
def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="High")

    return

"""
Kill the malicious process on the endpoint with the file name from the artifact.
"""
def terminate_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('terminate_process_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fileName', 'filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'terminate_process_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0] and filtered_artifacts_item_1[1]:
            parameters.append({
                'name': filtered_artifacts_item_1[0],
                'sensor': "example_sensor",
                'ip_hostname': filtered_artifacts_item_1[1],
                'action_group': "example_group",
                'package_name': "example_package",
                'timeout_seconds': 60,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[2]},
            })

    phantom.act(action="terminate process", parameters=parameters, assets=['tanium'], name="terminate_process_1")

    return

"""
Check a custom list to see if the IP address associated with the malicious file is already on a blocklist.
"""
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:blocked_ips"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Ask an analyst if the IP address should be blocked.
"""
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Based on a SIEM event about a potential malware incident, Phantom has investigated and determined that the potential attacker IP address:  
{0}

has been connected to malware with hash 
{1}

and the above hash has {2} positive detections on a ReversingLabs reputation score. Should Phantom temporarily block the IP address using the Palo Alto Networks firewall for the next 60 minutes (after which it will be unblocked)?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress",
        "filtered-data:filter_3:condition_1:artifact:*.cef.fileHash",
        "filtered-data:filter_2:condition_1:file_reputation_1:action_result.summary.positives",
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

"""
Check the analyst response.
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_to_block_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Add the IP address to a custom list of blocked IP addresses.
"""
def add_to_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_to_block_list() called')

    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress'])

    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    phantom.add_list("blocked_ips", filtered_artifacts_item_1_0)
    block_ip_1(container=container)

    return

"""
Create a new block rule on the firewall.
"""
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['pan'], callback=unblock_ip_1, name="block_ip_1")

    return

"""
After a time delay, unblock the IP address.
"""
def unblock_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unblock_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'unblock_ip_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_ip_1:action_result.parameter.ip', 'block_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'unblock_ip_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'vsys': "vsys1",
                'is_source_address': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })
    # calculate start time using delay of 60 minutes
    start_time = datetime.now() + timedelta(minutes=60)

    phantom.act(action="unblock ip", parameters=parameters, assets=['pan'], callback=remove_from_block_list, start_time=start_time, name="unblock_ip_1", parent_action=action)

    return

"""
Use custom code to remove the IP address from a blocklist.
"""
def remove_from_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_from_block_list() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # collect list of ip addresses
    ips_to_remove = phantom.collect2(container=container, datapath=['unblock_ip_1:action_result.parameter.ip'], action_results=results)
    
    phantom.debug("ips to remove: {}".format(ips_to_remove))
    del_rows = set()
    
    for ip in ips_to_remove:
        phantom.delete_from_list(list_name="blocked_ips", value=ip, column=0, remove_all=True, remove_row=True)

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/noop", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/noop', parameters=parameters, name='remove_from_block_list')

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