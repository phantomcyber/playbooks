"""
Investigate an AWS Security Hub finding related to an exposed EC2 instance which is being probed by potentially malicious traffic. Gather information about the EC2 configuration, the activity on the server, and any remote IP addresses that are directing traffic at the server. Notify and assign the appropriate people using a Jira ticket and a Slack message, then initiate a prompt to ask a responder whether or not the EC2 instance should be moved to an isolated EC2 Security Group using another playbook called "EC2 Instance Isolation".
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_severity_threshold' block
    decision_severity_threshold(container=container)

    return

"""
Gather metadata about the EC2 instance in the Finding.
"""
def describe_ec2_instance(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_ec2_instance() called')

    # collect data for 'describe_ec2_instance' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_resource_artifact:condition_1:artifact:*.cef.InstanceId', 'filtered-data:filter_resource_artifact:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'describe_ec2_instance' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'limit': "",
            'dry_run': "",
            'filters': "",
            'instance_ids': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="describe instance", parameters=parameters, assets=['aws_ec2'], callback=describe_ec2_instance_callback, name="describe_ec2_instance")

    return

def describe_ec2_instance_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('describe_ec2_instance_callback() called')
    
    build_finding_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_security_groups_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_firewall_rules_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_processes_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    list_connections_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    parse_remote_ip_addrs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
List the open network connections on the EC2 instance using SSH.
"""
def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Association.PublicDnsName', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)

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

    phantom.act(action="list connections", parameters=parameters, assets=['ssh'], callback=filter_ip_addresses, name="list_connections_1", parent_action=action)

    return

"""
Put together the relevant links, title, and description for the Finding to present to an analyst in both a ticket and a chat message.
"""
def format_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_description() called')
    
    template = """Phantom received a Security Hub Finding with the following details:

Finding title: {0}
Finding description: {1}
Phantom Mission Control link: {2}
AWS Security Hub Finding link: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:description",
        "container:url",
        "build_finding_url:custom_function:finding_url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_description")

    create_ticket_1(container=container)
    send_message_1(container=container)

    return

"""
Separate the EC2 resource from the other artifacts in the Finding.
"""
def filter_resource_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_resource_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ],
        name="filter_resource_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_finding_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Separate the main Finding artifact from the other artifacts in the Finding.
"""
def filter_finding_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_finding_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Finding Artifact"],
        ],
        name="filter_finding_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        describe_ec2_instance(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Only proceed if there is an EC2 Resource contained in the SecurityHub Finding.
"""
def decision_ec2_resource(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_ec2_resource() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "AwsEc2Instance Resource Artifact"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_resource_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Use the Finding ID to construct a URL with a pre-populated SecurityHub search to view the Finding in the AWS Console.
"""
def build_finding_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_finding_url() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_finding_artifact:condition_1:artifact:*.cef.Id'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    build_finding_url__finding_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # build a link to the Finding on Security Hub using a search as a URL parameter
    base = "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A"
    build_finding_url__finding_url = base + filtered_artifacts_item_1_0[0].replace(':', '%253A').replace('/', '%252F')
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='build_finding_url:finding_url', value=json.dumps(build_finding_url__finding_url))
    format_description(container=container)

    return

"""
List the security groups that the EC2 instance belongs to. This should show the potentially vulnerable configuration described by the Finding.
"""
def list_security_groups_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_security_groups_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_security_groups_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.SecurityGroups.*.GroupId', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_security_groups_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'dry_run': "",
            'filters': "",
            'group_ids': results_item_1[0],
            'next_token': "",
            'group_names': "",
            'max_results': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="list security groups", parameters=parameters, assets=['aws_ec2'], name="list_security_groups_1", parent_action=action)

    return

"""
List the host-based firewall rules on the EC2 instance using SSH.
"""
def list_firewall_rules_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_firewall_rules_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_firewall_rules_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Association.PublicDnsName', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_firewall_rules_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'port': "",
                'chain': "",
                'protocol': "",
                'ip_hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="list firewall rules", parameters=parameters, assets=['ssh'], name="list_firewall_rules_1", parent_action=action)

    return

"""
List the running processes on the EC2 instance using SSH.
"""
def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_processes_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.NetworkInterfaces.*.Association.PublicDnsName', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_processes_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip_hostname': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="list processes", parameters=parameters, assets=['ssh'], name="list_processes_1", parent_action=action)

    return

"""
Ask the analyst whether to isolate the EC2 instance using a change in security groups.
"""
def isolate_ec2_instance_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('isolate_ec2_instance_approval() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The playbook ec2_instance_investigation_and_notification has investigated the EC2 instance with ID {0} and name {1}. Should Phantom quarantine the instance by changing the instance's Security Group to disallow all traffic?"""

    # parameter list for template variable replacement
    parameters = [
        "describe_ec2_instance:action_result.parameter.instance_ids",
        "describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.Tags.Name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="isolate_ec2_instance_approval", parameters=parameters, response_types=response_types, callback=prompt_decision)

    return

def join_isolate_ec2_instance_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_isolate_ec2_instance_approval() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['create_ticket_1', 'send_message_1']):
        
        # call connected block "isolate_ec2_instance_approval"
        isolate_ec2_instance_approval(container=container, handle=handle)
    
    return

"""
Check the result from the previous prompt block.
"""
def prompt_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_decision() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["isolate_ec2_instance_approval:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_ec2_instance_isolation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_security_hub_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Call another playbook to isolate the EC2 instance as specified by the prompt.
"""
def playbook_local_ec2_instance_isolation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_ec2_instance_isolation_1() called')
    
    # call playbook "local/ec2_instance_isolation", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/ec2_instance_isolation", container=container)

    return

"""
Add the formatted note to the SecurityHub Finding.
"""
def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect data for 'add_note_2' call
    formatted_data_1 = phantom.get_format_data(name='format_security_hub_note')

    parameters = []
    
    # build parameters list for 'add_note_2' call
    parameters.append({
        'note': formatted_data_1,
        'overwrite': "",
        'findings_id': source_data_identifier_value,
    })

    phantom.act(action="add note", parameters=parameters, assets=['aws_security_hub'], name="add_note_2")

    return

"""
Format a note describing the "No" response from the prompt.
"""
def format_security_hub_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_security_hub_note() called')
    
    template = """Phantom investigated this incident and the analyst decided not to isolate this instance automatically. View the event in Phantom Mission Control here: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_security_hub_note")

    add_note_2(container=container)

    return

"""
Filter out the IP addresses that belong to the internal AWS VPC.
"""
def filter_ip_addresses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ip_addresses() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['list_connections_1:action_result.data.*.connections.*.remote_ip'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    filter_ip_addresses__connection_ip_addresses = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    filter_ip_addresses__connection_ip_addresses = []
    
    internal_cidr = "172.31.0.0/16"
    for ip in results_item_1_0:
        phantom.debug("checking ip {} against internal CIDR: {}".format(ip, internal_cidr))
        if phantom.address_in_network(ip, internal_cidr):
            phantom.debug("skipping ip {} because it matches the internal CIDR".format(ip))
            continue
        
        filter_ip_addresses__connection_ip_addresses.append(ip)
        
    # this block outputs all the non-internal ip addresses:
    phantom.debug("connection ip list:\n{}".format(filter_ip_addresses__connection_ip_addresses))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='filter_ip_addresses:connection_ip_addresses', value=json.dumps(filter_ip_addresses__connection_ip_addresses))
    connection_format_ip(container=container)

    return

"""
Turn the remaining IP addresses into a list to allow usage in an action.
"""
def connection_format_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('connection_format_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filter_ip_addresses:custom_function:connection_ip_addresses",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="connection_format_ip")

    connection_geolocate_ip(container=container)
    connection_ip_reputation(container=container)

    return

"""
Determine the geolocation of the IP addresses seen in network connections to the EC2 instance.
"""
def connection_geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('connection_geolocate_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'connection_geolocate_ip' call
    formatted_data_1 = phantom.get_format_data(name='connection_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'connection_geolocate_ip' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], name="connection_geolocate_ip")

    return

"""
Collect the remote IP addresses described in the Finding.
"""
def parse_remote_ip_addrs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parse_remote_ip_addrs() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_finding_artifact:condition_1:artifact:*.cef.ProductFields'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    parse_remote_ip_addrs__ip_addresses = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parse_remote_ip_addrs__ip_addresses = []
    
    product_fields = filtered_artifacts_item_1_0[0]
    for key in product_fields.keys():
        if 'remoteIpDetails/ipAddressV4' in key:
            parse_remote_ip_addrs__ip_addresses.append(product_fields[key])
    phantom.debug("remote ip addresses from finding:\n{}".format(parse_remote_ip_addrs__ip_addresses))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='parse_remote_ip_addrs:ip_addresses', value=json.dumps(parse_remote_ip_addrs__ip_addresses))
    finding_format_ip(container=container)

    return

"""
Turn the IP addresses from the Finding into a list to allow usage in an action.
"""
def finding_format_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_format_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "parse_remote_ip_addrs:custom_function:ip_addresses",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="finding_format_ip")

    finding_geolocate_ip(container=container)
    finding_ip_reputation(container=container)

    return

"""
Determine the geolocation of the IP addresses seen in the Finding.
"""
def finding_geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_geolocate_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'finding_geolocate_ip' call
    formatted_data_1 = phantom.get_format_data(name='finding_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'finding_geolocate_ip' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], name="finding_geolocate_ip")

    return

"""
Determine the reputation of the IP addresses seen in network connections to the EC2 instance.
"""
def connection_ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('connection_ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'connection_ip_reputation' call
    formatted_data_1 = phantom.get_format_data(name='connection_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'connection_ip_reputation' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
            'ph': "",
            'to': "",
            'from': "",
        })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], name="connection_ip_reputation")

    return

"""
Determine the reputation of the IP addresses seen in the Finding.
"""
def finding_ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('finding_ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'finding_ip_reputation' call
    formatted_data_1 = phantom.get_format_data(name='finding_format_ip__as_list')

    parameters = []
    
    # build parameters list for 'finding_ip_reputation' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
            'ph': "",
            'to': "",
            'from': "",
        })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], name="finding_ip_reputation")

    return

"""
Only proceed with this Finding if the SecurityHub normalized severity is above a certain threshold.
"""
def decision_severity_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_severity_threshold() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.Severity.Normalized", ">", 35],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_ec2_resource(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Create a ticket to track this incident.
"""
def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    name_value = container.get('name', None)

    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_description')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'fields': "",
        'summary': name_value,
        'assignee': "",
        'priority': "High",
        'vault_id': "",
        'issue_type': "Bug",
        'description': formatted_data_1,
        'project_key': "EK",
        'assignee_account_id': "",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['jira'], callback=join_isolate_ec2_instance_approval, name="create_ticket_1")

    return

"""
Determine the person responsible for managing the server based on a tag on the EC2 instance, and notify that person about the Finding and the potential remediation by Phantom using an individual Slack message .
"""
def send_message_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_message_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_message_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_ec2_instance:action_result.data.*.Reservations.*.Instances.*.Tags.InstanceOwnerSlack', 'describe_ec2_instance:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_description')

    parameters = []
    
    # build parameters list for 'send_message_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'message': formatted_data_1,
                'destination': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="send message", parameters=parameters, assets=['slack'], callback=join_isolate_ec2_instance_approval, name="send_message_1")

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