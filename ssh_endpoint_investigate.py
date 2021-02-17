"""
This playbook gathers basic system information from a CentOS 7 server using SSH. Phantom is configured to poll Jira for new tickets, and the investigation is kicked off automatically when a ticket with the tag "new_linux_server" is opened. The results of the SSH commands are formatted and added to the new Jira ticket as comments to help the analyst make a quick decision about how to handle the server. The first time one of these tickets comes through Phantom it will be turned into a Case, then any future tickets will be added to the existing Case to allow all of these servers to be treated as a batch.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_jira_key' block
    get_jira_key(container=container)

    return

"""
Only investigate tickets of type "new_linux_server" and only proceed for initial ticket creation (to prevent running again when the ticket is updated).
"""
def only_new_linux_server(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('only_new_linux_server() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket:action_result.data.*.fields.Custom Label Field Two.0", "==", "new_linux_server"],
            ["artifact:*.name", "==", "ticket fields"],
        ],
        logical_operator='and',
        name="only_new_linux_server:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        search_containers(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Run "/usr/bin/last -a" to see the login history.
"""
def get_login_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_login_history() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_login_history' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.data.*.fields.Custom Text Field One', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_login_history' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'command': "/usr/bin/last -a",
                'timeout': "",
                'ip_hostname': results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh'], callback=format_login, name="get_login_history")

    return

"""
Run "/usr/sbin/ss -tunapl" to see which services are listening on which TCP and UDP ports. Note that "ss" is very similar to "netstat", which is deprecated and no longer installed by default on CentOS 7.
"""
def list_open_ports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_open_ports() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_open_ports' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.data.*.fields.Custom Text Field One', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_open_ports' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'command': "/usr/sbin/ss -tunapl",
                'timeout': "",
                'ip_hostname': results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh'], callback=format_port_list, name="list_open_ports")

    return

"""
Extract the Jira Key (the project identifier plus the issue ID in the form ABC-1234) from the raw data of the container as ingested from Jira. 
"""
def get_jira_key(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_jira_key() called')
    
    input_parameter_0 = ""

    get_jira_key__jira_key = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    container_raw = phantom.get_raw_data(container)
    container_parsed = json.loads(container_raw)
    get_jira_key__jira_key = container_parsed['key']
    phantom.debug("using Jira ticket with key: {}".format(get_jira_key__jira_key))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_jira_key:jira_key', value=json.dumps(get_jira_key__jira_key))
    get_ticket(container=container)

    return

"""
Get the full ticket from Jira to use its metadata for future actions and make sure the ingested container references a valid ticket.
"""
def get_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ticket() called')

    get_jira_key__jira_key = json.loads(phantom.get_run_data(key='get_jira_key:jira_key'))
    # collect data for 'get_ticket' call

    parameters = []
    
    # build parameters list for 'get_ticket' call
    parameters.append({
        'id': get_jira_key__jira_key,
    })

    phantom.act(action="get ticket", parameters=parameters, assets=['jira'], callback=only_new_linux_server, name="get_ticket")

    return

"""
Search for all existing Phantom containers that match the string "new_linux_server" to find other similar containers.
"""
def search_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('search_containers() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'search_containers' call

    parameters = []
    
    # build parameters list for 'search_containers' call
    parameters.append({
        'headers': "",
        'location': "/rest/search?query=new_linux_server&page_size=0&categories=container",
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['http'], callback=format_get_containers, name="search_containers")

    return

"""
Check if any of the identified containers from the search have been promoted to a case and have the tag "new_linux_server". If a match is found, merge this container into that existing case to work with all of these servers in one place. If no matching case is found, promote this container to a case and use that going forward.
"""
def promote_or_add_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_or_add_to_case() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_containers:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    found_case = False
    
    for result_container in results_item_1_0:
        if result_container['container_type'] == 'case' and result_container['data']['fields']['customfield_10201'][0] == 'new_linux_server':
            phantom.debug("found matching case with id {}, so this container (id {}) will be added to that case".format(result_container['id'], container['id']))
            phantom.merge(case=result_container['id'], container_id=container['id'])
            found_case = True
    
    if not found_case:
        # if the loop finishes no case was found, so this is the first one and it should be promoted to a case
        phantom.debug("did not find matching case, so this container (id {}) will be promoted to a case".format(container['id']))
        phantom.promote(container=container, template="Vulnerability Disclosure", trace=True)

    ################################################################################
    ## Custom Code End
    ################################################################################
    check_centos_version(container=container)

    return

"""
Format an HTTP GET request to send to this local Phantom instance to pull down all the metadata from each container found by the previous search.
"""
def format_get_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_get_containers() called')
    
    template = """%%
/rest/container/{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "search_containers:action_result.data.*.response_body.results.*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_get_containers")

    get_containers(container=container)

    return

"""
Run the formatted HTTP GET request to pull the metadata about all identified containers.
"""
def get_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_containers() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_containers' call
    formatted_data_1 = phantom.get_format_data(name='format_get_containers__as_list')

    parameters = []
    
    # build parameters list for 'get_containers' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'headers': "",
            'location': formatted_part_1,
            'verify_certificate': False,
        })

    phantom.act(action="get data", parameters=parameters, assets=['http'], callback=promote_or_add_to_case, name="get_containers")

    return

"""
Read the contents of the /etc/redhat-release file on the server to check the CentOS version.
"""
def check_centos_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_centos_version() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'check_centos_version' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.data.*.fields.Custom Text Field One', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'check_centos_version' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'command': "cat /etc/redhat-release",
                'timeout': "",
                'ip_hostname': results_item_1[0],
                'script_file': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="execute program", parameters=parameters, assets=['ssh'], callback=fail_unless_centos7, name="check_centos_version")

    return

"""
This playbook was developed and tested for CentOS 7 servers, so this checks to make sure the target server is running CentOS 7.
"""
def fail_unless_centos7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fail_unless_centos7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["CentOS Linux release 7", "in", "check_centos_version:action_result.data.*.output"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_login_history(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        list_open_ports(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    report_failure(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Leave a comment on the Jira ticket saying that the server is not running CentOS 7 therefore this playbook doesn't know how to handle it.
"""
def report_failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('report_failure() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'report_failure' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.parameter.id', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'report_failure' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'comment': "Phantom failed to enrich this ticket because it looks like the server is not running CentOS 7, which is the only operating system supported by this playbook.",
                'internal': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add comment", parameters=parameters, assets=['jira'], name="report_failure")

    return

"""
Format the output of "last -a" into a table.
"""
def format_login(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_login() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_login_history:action_result.data.*.output'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    format_login__login_table = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # format the output into Jira's markup language for rendering a table
    format_login__login_table = "|| output of '/usr/bin/last -a' ||\n"
    last_lines = results_item_1_0[0].split('\n')
    for line in last_lines:
        format_login__login_table += "| {} |\n".format(line)
    
    phantom.debug("table of logins for jira:")
    phantom.debug(format_login__login_table)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_login:login_table', value=json.dumps(format_login__login_table))
    enrich_ticket_1(container=container)

    return

"""
Format the output of "ss -tunapl"  into a table.
"""
def format_port_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_port_list() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['list_open_ports:action_result.data.*.output'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    format_port_list__port_table = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # format the output into Jira's markup language for rendering a table
    format_port_list__port_table = "|| protocol || state || recv-q || send-q || local_address:port || peer_address:port ||\n"
    lines = results_item_1_0[0].split('\n')[1:]
    for line in lines:
        
        protocol, state, recv, send, local_address_port, peer_address_port = line.split()
        format_port_list__port_table += "| {} | {} | {} | {} | {} | {} |\n".format(protocol,
                                                                        state,
                                                                        recv,
                                                                        send,
                                                                        local_address_port,
                                                                        peer_address_port)

    phantom.debug("table of ports for jira:")
    phantom.debug(format_port_list__port_table)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_port_list:port_table', value=json.dumps(format_port_list__port_table))
    enrich_ticket_2(container=container)

    return

"""
Enrich the ticket with the table of previous logins.
"""
def enrich_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    format_login__login_table = json.loads(phantom.get_run_data(key='format_login:login_table'))
    # collect data for 'enrich_ticket_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.parameter.id', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'enrich_ticket_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'comment': format_login__login_table,
                'internal': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add comment", parameters=parameters, assets=['jira'], name="enrich_ticket_1")

    return

"""
Enrich the ticket with the table of open ports.
"""
def enrich_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    format_port_list__port_table = json.loads(phantom.get_run_data(key='format_port_list:port_table'))
    # collect data for 'enrich_ticket_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket:action_result.parameter.id', 'get_ticket:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'enrich_ticket_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'comment': format_port_list__port_table,
                'internal': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="add comment", parameters=parameters, assets=['jira'], name="enrich_ticket_2")

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