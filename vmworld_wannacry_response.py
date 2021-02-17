"""
In virtualized environments the ability to take snapshots of VM's allows incident response systems to save crucial data from encryption, but only if the snapshot is triggered before encryption finishes. This is an area where security automation can play a particularly important role. In this playbook Phantom receives an alert from Vectra Cognito signifying that a ransomware variant such as Wannacry has been detected on one or more endpoints within the network. Phantom immediately snapshots the affected devices that are virtual machines managed by vSphere, and blocks command and control traffic using the VMWare NSX virtual firewall. Beyond that immediate response the security team is also asked whether or not to quarantine the affected hosts with Carbon Black.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'NSX_block_port' block
    NSX_block_port(container=container)

    # call 'vsphere_list_vms' block
    vsphere_list_vms(container=container)

    return

"""
Acquire the full list of vSphere virtual machines to determine which were affected.
"""
def vsphere_list_vms(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('vsphere_list_vms() called')

    parameters = []

    phantom.act(action="list vms", parameters=parameters, assets=['vmwarevsphere'], callback=filter_1, name="vsphere_list_vms")

    return

"""
Prompt the incident response team before quarantining devices.
"""
def should_quarantine_devices_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('should_quarantine_devices_prompt() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following host has automatically had a block port rule deployed to it in response to a potential WannaCry sighting: 
{0}

Do you want to proceed with a full quarantine of these hosts?  Yes/No"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="should_quarantine_devices_prompt", parameters=parameters, response_types=response_types, callback=decision_1)

    return

"""
Proceed to snapshot with virtual machines that were detected in the Vectra alert.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["vsphere_list_vms:action_result.data.*.ip", "==", "artifact:*.cef.sourceAddress"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Take a snapshot of each affected virtual machine to attempt to save data from encryption.
"""
def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:vsphere_list_vms:action_result.data.*.vmx_path", "filtered-data:filter_1:condition_1:vsphere_list_vms:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'download': "",
                'vmx_path': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="snapshot vm", parameters=parameters, assets=['vmwarevsphere'], name="snapshot_vm_1")

    return

"""
Use the virtual firewall to block command and control traffic by the ransomware.
"""
def NSX_block_port(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('NSX_block_port() called')

    # collect data for 'NSX_block_port' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'NSX_block_port' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['vmwarensx'], callback=should_quarantine_devices_prompt, name="NSX_block_port")

    return

"""
Use a ticketing system to request further investigation of the ransomware alert.
"""
def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Wanna Cry Endpoints Affected - No Quarantine",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_1")

    return

"""
Isolate the devices from the rest of the network to prevent malware propagation.
"""
def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantine_device_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'quarantine_device_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['NSX_block_port:action_result.parameter.ip', 'NSX_block_port:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'quarantine_device_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip_hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="quarantine device", parameters=parameters, assets=['carbonblack'], name="quarantine_device_1")

    return

"""
Check the yes or no response from the prompt.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["should_quarantine_devices_prompt:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        quarantine_device_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_ticket(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format a message to create a ticket if the devices are not being quarantined.
"""
def format_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket() called')
    
    template = """The following endpoints were affected:
{0}

An incident responder determined that the affected hosts should not be qurantined, but they can be reviewed further and quarantined later in Mission Control."""

    # parameter list for template variable replacement
    parameters = [
        "NSX_block_port:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket")

    create_ticket_1(container=container)

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