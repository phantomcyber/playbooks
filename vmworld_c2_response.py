"""
This Playbook demonstrates a response to a command and control alert when an organization is operating a VMWare virtualized environment. The individual endpoints are vSphere guests and the network stack is virtualized with VMWare NSX. This allows unique response options including virtual machine snapshots and the flexible deployment of new firewall rules across dynamic infrastructure. We built this Playbook in a partnership with Rackspace and VMWare. As one of the largest vSphere service providers, Rackspace provides experienced insight into the deployment of security automation and orchestration in the virtualized datacenter.

VMWorld 2017 Demonstration: https://rackconnection.rackspace.com/youtube-us-region/powering-next-level-security-with-vmware-technology
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_3' block
    filter_3(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    # call 'filter_1' block
    filter_1(container=container)

    # call 'list_vms_1' block
    list_vms_1(container=container)

    return

"""
Use custom thresholds to categorize high and low severity events based on the IP reputation from Virustotal and Threatstream.
"""
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation:action_result.data.*.detected_urls.*.positives", ">=", 15],
            ["ip_reputation:action_result.data.*.threatscore", ">=", 60],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_high(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_low(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_3() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['ip_reputation', 'file_reputation']):
        
        # call connected block "decision_3"
        decision_3(container=container, handle=handle)
    
    return

"""
Now that our Virustotal threshold has classified the file as malicious we will use CarbonBlack Response to block future executions of that file.
"""
def block_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash' call
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation:action_result.parameter.hash', 'file_reputation:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_hash' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                'comment': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], name="block_hash")

    return

"""
Only proceed if 20 or more detection engines in Virustotal classified the file as malicious.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation:action_result.summary.positives", ">=", 20],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        block_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Set the severity of this event to Low.
"""
def set_severity_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_low() called')

    phantom.set_severity(container=container, severity="low")
    set_status_resolved_2(container=container)

    return

"""
Resolve this event. The enrichment and the history of any blocking actions taken can still be reviewed in Mission Control and reopened if further action is necessary.
"""
def set_status_resolved(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_resolved() called')

    phantom.set_status(container=container, status="closed")

    return

"""
Resolve this event. The enrichment and the history of any blocking actions taken can still be reviewed in Mission Control and reopened if further action is necessary.
"""
def set_status_resolved_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_resolved_2() called')

    phantom.set_status(container=container, status="closed")

    return

"""
Query reputation aggregators to determine whether the given hashes represent known malware.
"""
def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation() called')

    # collect data for 'file_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fileHashMd5', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=file_reputation_callback, name="file_reputation")

    return

def file_reputation_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('file_reputation_callback() called')
    
    decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    join_decision_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Take snapshots of the detected virtual machines in case they are needed for forensics or recovery.
"""
def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:list_vms_1:action_result.data.*.vmx_path", "filtered-data:filter_4:condition_1:list_vms_1:action_result.parameter.context.artifact_id"])

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
Set the severity of this event to High.
"""
def set_severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_high() called')

    phantom.set_severity(container=container, severity="high")
    set_status_resolved(container=container)

    return

"""
Query the PhishMe Intelligence platform for threat information about files with the given MD5 hash.
"""
def hunt_file_md5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_md5() called')

    # collect data for 'hunt_file_md5' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fileHashMd5', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_md5' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                'max_threat_count': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="hunt file", parameters=parameters, assets=['phishme'], name="hunt_file_md5")

    return

"""
Query for threat information and observations about the given IP address.
"""
def hunt_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_ip_1() called')

    # collect data for 'hunt_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'max_threat_count': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="hunt ip", parameters=parameters, assets=['phishme'], name="hunt_ip_1")

    return

"""
List all VMWare virtual machines to check if any snap shots should be taken.
"""
def list_vms_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_vms_1() called')

    parameters = []

    phantom.act(action="list vms", parameters=parameters, assets=['vmwarevsphere'], callback=filter_4, name="list_vms_1")

    return

"""
Query across all the data sources integrated into Protectwise for observations of the given SHA-256 file hash.
"""
def hunt_file_sha256(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_sha256() called')

    # collect data for 'hunt_file_sha256' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.fileHashSha256', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_sha256' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ph': "",
                'hash': filtered_artifacts_item_1[0],
                'end_time': "",
                'start_time': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="hunt file", parameters=parameters, assets=['protectwise'], name="hunt_file_sha256")

    return

"""
Filter the artifacts with SHA-256 file hashes.
"""
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha256", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_file_sha256(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter the artifacts with MD5 file hashes.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_md5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter the artifacts with destination IP addresses.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        ip_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Query reputation services to determine whether the given IP address is known-good, known-bad, or unknown.
"""
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation() called')

    # collect data for 'ip_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=ip_reputation_callback, name="ip_reputation")

    return

def ip_reputation_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ip_reputation_callback() called')
    
    decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    join_decision_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Only proceed with source addresses of virtual machines.
"""
def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_vms_1:action_result.data.*.ip", "==", "artifact:*.cef.sourceAddress"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Only proceed for IP's that resolved to 15 or more positives.
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation:action_result.data.*.detected_urls.*.positives", ">=", 15],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        NSX_block_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Now that we have determined that an IP is probably malicious we can add an NSX rule to block access to it.
"""
def NSX_block_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('NSX_block_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'NSX_block_IP' call
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation:action_result.data.*.ip', 'ip_reputation:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'NSX_block_IP' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['vmwarensx'], name="NSX_block_IP")

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