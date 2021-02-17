"""
When a suspicious URL is detected, this playbook can be used to identify internal devices that have accessed that URL and triage the organizational importance of those devices. Then, depending on the maliciousness of the URL and whether or not the affected device belongs to an executive in the organization,  the URL will be blocked and an appropriate ServiceNow ticket will be created.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'url_reputation_2' block
    url_reputation_2(container=container)

    return

"""
Check for existing scans of this URL on Virustotal.
"""
def url_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_2() called')

    # collect data for 'url_reputation_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="url_reputation_2")

    return

"""
Continue if the URL has over 4 positive scans.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_2:action_result.summary.positives", ">", 4],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_splunk_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Match back to the username of the executive.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_1:action_result.data.*.User", "==", "filtered-data:filter_1:condition_1:get_user_attributes_1:action_result.parameter.username"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        exec_short_description(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Match back to the non-executive username.
"""
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_1:action_result.data.*.User", "==", "filtered-data:filter_1:condition_2:get_user_attributes_1:action_result.parameter.username"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        quarantine_regular_device(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check the prompt response.
"""
def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        quarantine_exec_device(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Since the prompt was confirmed, quarantine the executive's device.
"""
def quarantine_exec_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantine_exec_device() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'quarantine_exec_device' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:run_query_1:action_result.data.*.client_ip", "filtered-data:filter_2:condition_1:run_query_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'quarantine_exec_device' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip_hostname': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="quarantine device", parameters=parameters, assets=['carbonblack'], name="quarantine_exec_device")

    return

"""
Build a Splunk query to check the zScaler proxy logs for events where the given URL was requested.
"""
def format_splunk_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_splunk_query() called')
    
    template = """host=\"zscalertwo-phantom\" index=\"proxy_logs_zscaler\" sourcetype=\"csv\"  | eval cleansed_url=replace(\"{0}\", \"http[s]*\\:\\/\\/\", \"\") | where URL=cleansed_url | rename \"Client IP\" as client_ip \"Policy Action\" as policy_action, \"URL Class\" as url_class, \"URL Category\" as url_category | fields client_ip, policy_action, url_class, url_category, User"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_2:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_splunk_query")

    run_query_1(container=container)

    return

"""
Run the Splunk query built in the previous format block.
"""
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_1' call
    formatted_data_1 = phantom.get_format_data(name='format_splunk_query')

    parameters = []
    
    # build parameters list for 'run_query_1' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "client_ip, url, url_category, url_class, User",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk_es'], callback=get_user_attributes_1, name="run_query_1")

    return

"""
Query Active Directory for information about the username retrieved from Splunk.
"""
def get_user_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_user_attributes_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_1:action_result.data.*.User', 'run_query_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_user_attributes_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'fields': "",
                'username': results_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, app={ "name": 'LDAP' }, callback=decision_5, name="get_user_attributes_1", parent_action=action)

    return

"""
Only proceed if the URL request was allowed by zScaler.
"""
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_1:action_result.data.*.policy_action", "==", "Allowed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        lookup_url_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Query zScaler to retrieve the URL classification and categorization.
"""
def lookup_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_url_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_url_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_url_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="lookup url", parameters=parameters, app={ "name": 'Zscaler' }, callback=zscaler_category_filter, name="lookup_url_2")

    return

"""
Block URL's with security classifications.
"""
def block_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_url_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:zscaler_category_filter:condition_1:lookup_url_2:action_result.parameter.url", "filtered-data:zscaler_category_filter:condition_1:lookup_url_2:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'block_url_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'url': filtered_results_item_1[0],
                'url_category': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="block url", parameters=parameters, assets=['zscaler'], name="block_url_2")

    return

"""
Handle the situation differently if the user is in the Executives department.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attributes_1:action_result.data.*.department", "==", "Executives"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attributes_1:action_result.data.*.department", "!=", "Executives"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format the short description (title) of the ticket.
"""
def regular_short_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('regular_short_description() called')
    
    template = """Endpoint connected to malicious URL - {0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:run_query_1:action_result.data.*.client_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="regular_short_description")

    regular_long_description(container=container)

    return

"""
Format the long-form description of the ticket.
"""
def regular_long_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('regular_long_description() called')
    
    template = """Endpoint as trying to access a known bad URL:
{0}

Positives from VirusTotal: {1}

Link to Phantom Incident: 
https://172.16.22.128/mission/{3}

Splunk Results: 
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
        "url_reputation_2:action_result.summary.positives",
        "filtered-data:filter_3:condition_1:run_query_1:action_result.data.*._raw",
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="regular_long_description")

    create_regular_ticket(container=container)

    return

"""
Create the ServiceNow ticket with the formatted short description and long description.
"""
def create_regular_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_regular_ticket() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_regular_ticket' call
    formatted_data_1 = phantom.get_format_data(name='regular_long_description')
    formatted_data_2 = phantom.get_format_data(name='regular_short_description')

    parameters = []
    
    # build parameters list for 'create_regular_ticket' call
    parameters.append({
        'table': "incident",
        'fields': "{\"urgency\":\"2\"}",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': formatted_data_2,
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_regular_ticket")

    return

"""
Format the short description (title) of the ticket.
"""
def exec_short_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('exec_short_description() called')
    
    template = """Please Investigate Executive Workstation - {0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:run_query_1:action_result.data.*.client_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="exec_short_description")

    exec_long_description(container=container)

    return

"""
Format the long-form description of the ticket.
"""
def exec_long_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('exec_long_description() called')
    
    template = """Executive was trying to access a known bad URL:
{0}

Positives from VirusTotal: {1}

Link to Phantom Incident: 
https://172.16.22.128/mission/{3}

Splunk Results: 
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
        "url_reputation_2:action_result.summary.positives",
        "filtered-data:filter_2:condition_1:run_query_1:action_result.data.*._raw",
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="exec_long_description")

    create_exec_ticket(container=container)

    return

"""
Create the ServiceNow ticket with the formatted short description and long description.
"""
def create_exec_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_exec_ticket() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_exec_ticket' call
    formatted_data_1 = phantom.get_format_data(name='exec_long_description')
    formatted_data_2 = phantom.get_format_data(name='exec_short_description')

    parameters = []
    
    # build parameters list for 'create_exec_ticket' call
    parameters.append({
        'table': "incident",
        'fields': "{\"urgency\":\"1\"}",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': formatted_data_2,
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_exec_ticket")

    return

"""
Since this is an executive, prompt an analyst before quarantining.
"""
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """High priority asset has visited malicious URL. Please review and determine if device should be quarantined?"""

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", response_types=response_types, callback=decision_7)

    return

"""
Quarantine the non-executive device.
"""
def quarantine_regular_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantine_regular_device() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'quarantine_regular_device' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:run_query_1:action_result.data.*.client_ip", "filtered-data:filter_3:condition_1:run_query_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'quarantine_regular_device' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip_hostname': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="quarantine device", parameters=parameters, assets=['carbonblack'], callback=regular_short_description, name="quarantine_regular_device")

    return

"""
If there is a security classification, meaning zScaler has identified something malicious about the URL, then proceed to block it.
"""
def zscaler_category_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('zscaler_category_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["lookup_url_2:action_result.data.*.urlClassificationsWithSecurityAlert", "!=", ""],
        ],
        name="zscaler_category_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_url_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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