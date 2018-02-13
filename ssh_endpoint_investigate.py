"""
This playbook gathers basic system information from a CentOS 7 server using SSH. The investigation is kicked off automatically when the right type of Jira ticket is opened. The results of the SSH commands are formatted and added to the new Jira ticket as comments to help the analyst make a quick decision about how to handle the server. The first time one of these tickets comes through Phantom it will be turned into a Case, then any future tickets will be added to the existing Case to allow all of these servers to be treated as a batch.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import requests

requests.packages.urllib3.disable_warnings()  # pylint: disable=E1101

AUTOMATION_HEADER = {"ph-auth-token": "s43OVieY63GXAhXuC2fIPljDv5sVNksjH+B+5V2qlYc="}
PHANTOM_BASE_URL = "https://phantom"
PHANTOM_SELF_SIGNED_PATH = "/opt/phantom/etc/certs/this_phantom_self_signed.pem"

def find_matching_case(linking_tag):

    # use elasticsearch to find the linking_tag anywhere it might be
    search_url = "{}/rest/search?query={}&page_size=0".format(PHANTOM_BASE_URL, linking_tag)
    search_results = requests.get(search_url, headers=AUTOMATION_HEADER, verify=PHANTOM_SELF_SIGNED_PATH).json()

    # look at each returned container with a matching field to see if its a case
    case_id = None
    for result in search_results['results']:
        if result['category'] == 'container':
            container_result = requests.get("{}/rest/container/{}".format(PHANTOM_BASE_URL, result['id']),
                                            headers=AUTOMATION_HEADER, verify=PHANTOM_SELF_SIGNED_PATH).json()
            
            phantom.debug("looking at container: {}".format(container_result))
            
            if container_result['container_type'] == 'case':
                if container_result['data']['fields']['customfield_10201'][0] == linking_tag:
                    if container_result['status'] != "closed":
                        case_id = container_result['id']
                        return case_id
    return None

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_ticket_1' block
    get_ticket_1(container=container)

    return

"""
Only investigate tickets of type "new_linux_server".
"""
def only_new_linux_server(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('only_new_linux_server() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_1:action_result.data.*.fields.Custom Label Field Two.0", "==", "new_linux_server"],
        ],
        name="only_new_linux_server:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        promote_to_case(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
This playbook was developed and tested for CentOS 7 servers, so this checks to make sure the target server is running CentOS 7.
"""
def fail_unless_centos7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('fail_unless_centos7() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["CentOS Linux release 7", "in", "check_centos_version:action_result.data.*.output"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        get_login_history(action=action, success=success, container=container, results=results, handle=handle)
        list_open_ports(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    report_failure(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Format the output of "ss -tunapl" and add it to the Jira ticket as a Jira-markup table in a comment.
"""
def enrich_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('enrich_ticket_2() called')
        
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect the data from the output of the ss command
    full_result = phantom.collect2(container=container, datapath=['list_open_ports:action_result.data.*.output', 'list_open_ports:action_result.parameter.context.artifact_id'], action_results=results)
    
    # parse the results from ss into Jira-flavored markdown
    comment_text = "|| protocol || state || recv-q || send-q || local_address:port || peer_address:port || users ||\n"
    lines = full_result[0][0].split('\n')[1:]
    for line in lines:
        protocol, state, recv, send, local_address_port, peer_address_port, users = line.split()
        comment_text += "| {} | {} | {} | {} | {} | {} | {} |\n".format(protocol,
                                                                        state,
                                                                        recv,
                                                                        send,
                                                                        local_address_port,
                                                                        peer_address_port,
                                                                        users.replace(":(", ": ("))
    
    phantom.debug("comment_text: {}".format(comment_text))
    
    parameters = []
    
    # build parameters list for 'add_ss_comment' call
    parameters.append({
        'id': source_data_identifier_value,
        'comment': comment_text,
    })

    phantom.act("add comment", parameters=parameters, assets=['jira'], name="add_ss_comment", parent_action=action)    
    
    return

"""
Search for a Case that was created from this type of Jira ticket. If there is none, promote this container to a Case. If there is a matching Case, add this container to that Case.
"""
def promote_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case() called')

    matching_case = find_matching_case("new_linux_server")

    if matching_case:
        phantom.debug("found matching case with id {}, so this container (id {}) will be added to that case".format(matching_case, container['id']))
        phantom.merge(case=matching_case, container_id=container['id'])
    else:
        phantom.debug("did not find matching case, so this container will be promoted to a case")
        phantom.promote(container=container, template="NIST 800-61", trace=True)
    
    check_centos_version(container=container)

    return

"""
Pull the ticket from Jira to use its metadata for future actions and make sure the ingested container references a valid ticket.
"""
def get_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_ticket_1() called')

    # the jira key is the ticket name such as ABC-3368, which can be pulled from the ticket container's raw data
    container_raw = phantom.get_raw_data(container)
    container_parsed = json.loads(container_raw)
    jira_key = container_parsed['key']
    phantom.debug("using Jira ticket with key: {}".format(jira_key))
    
    parameters = [{'id': jira_key,}]
    phantom.act("get ticket", parameters=parameters, assets=['jira'], callback=only_new_linux_server, name="get_ticket_1")    
    
    return

"""
Run "/usr/bin/last -a" to see the login history.
"""
def get_login_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_login_history() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_login_history' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.*.fields.Custom Text Field One', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_login_history' call
    for results_item_1 in results_data_1:
        parameters.append({
            'command': "/usr/bin/last -a",
            'ip_hostname': results_item_1[0],
            'timeout': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act("execute program", parameters=parameters, assets=['ssh'], callback=enrich_ticket_1, name="get_login_history")

    return

"""
Run "/usr/sbin/ss -tunapl" to see which services are listening on which TCP and UDP ports. Note that "ss" is very similar to "netstat", which is deprecated and no longer installed by default on CentOS 7.
"""
def list_open_ports(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('list_open_ports() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_open_ports' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.*.fields.Custom Text Field One', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_open_ports' call
    for results_item_1 in results_data_1:
        parameters.append({
            'command': "/usr/sbin/ss -tunapl",
            'ip_hostname': results_item_1[0],
            'timeout': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act("execute program", parameters=parameters, assets=['ssh'], callback=enrich_ticket_2, name="list_open_ports")

    return

"""
Format the output of "last -a" and add it to the Jira ticket as a Jira-markup table in a comment.
"""
def enrich_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('enrich_ticket_1() called')
        
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect the login history from the SSH command result
    full_last_result = phantom.collect2(container=container, datapath=['get_login_history:action_result.data.*.output', 'get_login_history:action_result.parameter.context.artifact_id'], action_results=results)

    # format the output into Jira's markup language for making a table
    comment_text = "|| output of '/usr/bin/last -a' ||\n"
    last_lines = full_last_result[0][0].split('\n')
    for line in last_lines:
        comment_text += "| {} |\n".format(line)
    
    parameters = []
    
    parameters.append({
        'id': source_data_identifier_value,
        'comment': comment_text,
        'context': {'artifact_id': container.get('id', None)},
    })

    phantom.act("add comment", parameters=parameters, assets=['jira'], name="add_comment_2", parent_action=action)    
    
    return

"""
Leave a comment on the Jira ticket saying that the server is not running CentOS 7 therefore this playbook doesn't know how to handle it.
"""
def report_failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('report_failure() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    source_data_identifier_value = container.get('source_data_identifier', None)

    # collect data for 'report_failure' call

    parameters = []
    
    # build parameters list for 'report_failure' call
    parameters.append({
        'comment': "Phantom failed to enrich this ticket because it looks like the server is not running CentOS 7, which is the only operating system supported by this playbook.",
        'id': source_data_identifier_value,
    })

    phantom.act("add comment", parameters=parameters, assets=['jira'], name="report_failure")

    return

"""
Read the contents of /etc/redhat-release on the server to enable fail_unless_centos7().
"""
def check_centos_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_centos_version() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'check_centos_version' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.*.fields.Custom Text Field One', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'check_centos_version' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'command': "cat /etc/redhat-release",
                'ip_hostname': results_item_1[0],
                'timeout': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("execute program", parameters=parameters, assets=['ssh'], callback=fail_unless_centos7, name="check_centos_version")

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