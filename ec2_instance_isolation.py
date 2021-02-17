"""
Isolate an EC2 instance by changing its security group in order to protect it from malicious traffic. This playbook can be started alone or used from another playbook after doing investigation and notification. The existing security group is removed from the instance and a new isolation security group is added.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_ec2_resource' block
    filter_ec2_resource(container=container)

    return

"""
Separate the EC2 resource from the other artifacts in the Finding.
"""
def filter_ec2_resource(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ec2_resource() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ],
        name="filter_ec2_resource:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        describe_instance_before(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Gather EC2 instance metadata before making any changes.
"""
def describe_instance_before(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_instance_before() called')

    # collect data for 'describe_instance_before' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_ec2_resource:condition_1:artifact:*.cef.InstanceId', 'filtered-data:filter_ec2_resource:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'describe_instance_before' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=add_isolation_SG, name="describe_instance_before")

    return

"""
Add the isolation security group to the EC2 instance.
"""
def add_isolation_SG(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_isolation_SG() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_isolation_SG' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.parameter.instance_ids', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_isolation_SG' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'group_id': "sg-009121c0a21b3b2e0",
                'instance_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="assign instance", parameters=parameters, assets=['aws_ec2'], callback=remove_existing_SGs, name="add_isolation_SG", parent_action=action)

    return

"""
Remove any pre-existing security groups that were part of the insecure configuration.
"""
def remove_existing_SGs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_existing_SGs() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'remove_existing_SGs' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.data.*.Reservations.*.Instances.*.SecurityGroups.*.GroupId', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['add_isolation_SG:action_result.parameter.instance_id', 'add_isolation_SG:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'remove_existing_SGs' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'group_id': results_item_1[0],
                    'instance_id': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="remove instance", parameters=parameters, assets=['aws_ec2'], callback=describe_instance_after, name="remove_existing_SGs", parent_action=action)

    return

"""
Gather EC2 instance metadata after changing the security groups to verify the change.
"""
def describe_instance_after(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_instance_after() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'describe_instance_after' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_before:action_result.parameter.instance_ids', 'describe_instance_before:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'describe_instance_after' call
    for results_item_1 in results_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=describe_instance_after_callback, name="describe_instance_after", parent_action=action)

    return

def describe_instance_after_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('describe_instance_after_callback() called')
    
    format_before(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    format_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_connections_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Combine the before and after messages into a single comment.
"""
def format_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_comment() called')
    
    template = """Before this playbook run the instance {0} had the following security groups:

{1}

and after this playbook run the instance has the following security groups:

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.parameter.instance_ids",
        "format_before:formatted_data",
        "format_after:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_comment")

    add_comment_1(container=container)

    return

"""
Format a message describing the security groups before the change.
"""
def format_before(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_before() called')
    
    template = """%%
Security Group ID: {0}
Security Group Name: {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupId",
        "describe_instance_before:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_before")

    format_after(container=container)

    return

"""
Format a message describing the security groups after the change.
"""
def format_after(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_after() called')
    
    template = """%%
Security Group ID: {0}
Security Group Name: {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_after:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupId",
        "describe_instance_after:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Groups.*.GroupName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_after")

    format_comment(container=container)

    return

"""
Post a comment describing the security group assignment before and after the change.
"""
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_comment')

    phantom.comment(container=container, comment=formatted_data_1)

    return

"""
Add a note to the Security Hub Finding to describe the change that was made.
"""
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect data for 'add_note_1' call
    formatted_data_1 = phantom.get_format_data(name='format_note')

    parameters = []
    
    # build parameters list for 'add_note_1' call
    parameters.append({
        'note': formatted_data_1,
        'overwrite': "",
        'findings_id': source_data_identifier_value,
    })

    phantom.act(action="add note", parameters=parameters, assets=['aws_security_hub'], name="add_note_1")

    return

"""
Format a note to add to the Finding in Security Hub.
"""
def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_note() called')
    
    template = """Phantom ran two playbooks investigating the EC2 instance {0} and isolating it from external networks by removing its previous security groups and assigning it to a quarantine security group. The event can be reviewed and further response can be taken using Mission Control in Phantom: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_before:action_result.parameter.instance_ids",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    add_note_1(container=container)

    return

"""
List active TCP and UDP connections to show which traffic is still reaching the instance and to show that Phantom still has SSH access to the instance.
"""
def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_after:action_result.data.*.Reservations.*.Instances.*.PublicDnsName', 'describe_instance_after:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'local_addr': "",
                'local_port': "",
                'ip_hostname': results_item_1[0],
                'remote_addr': "",
                'remote_port': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="list connections", parameters=parameters, assets=['ssh'], name="list_connections_1", parent_action=action)

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