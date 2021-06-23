"""
Extract and enrich domain names in a suspicious email. This operates on domain names automatically extracted at email ingestion as well as domain names extracted within this playbook using the regex_extract_email custom function. Once the domain names are extracted, Cisco Umbrella Investigate is used to gather reputation information, including risk scores, which are presented in a note within the event.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'extracted_domains' block
    extracted_domains(container=container)

    # call 'get_full_event_text' block
    get_full_event_text(container=container)

    return

"""
Use a regular expression to extract all email addresses from the full text of the event.
"""
def extract_email_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_email_domains() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['get_full_event_text:custom_function_result.data.*.item'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/regex_extract_email", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/regex_extract_email', parameters=parameters, name='extract_email_domains', callback=email_domain_rep)

    return

"""
Proceed with domains extracted into artifacts at ingestion.
"""
def extracted_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extracted_domains() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="extracted_domains:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        artifact_domain_rep(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Using the domains that were automatically extracted from the email at ingestion, gather the reputation of those domain names.
"""
def artifact_domain_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifact_domain_rep() called')

    # collect data for 'artifact_domain_rep' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:extracted_domains:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:extracted_domains:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'artifact_domain_rep' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['umbrella_investigate'], callback=artifact_non_malicious, name="artifact_domain_rep")

    return

"""
Using the domain portion of the extracted emails, gather the reputation of those domain names.
"""
def email_domain_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('email_domain_rep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'email_domain_rep' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['extract_email_domains:custom_function_result.data.*.domain'], action_results=results)

    parameters = []
    
    # build parameters list for 'email_domain_rep' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'domain': custom_function_results_item_1[0],
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['umbrella_investigate'], callback=extracted_non_malicious, name="email_domain_rep")

    return

"""
Fetch the full text of the event, including all the artifacts.
"""
def get_full_event_text(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_full_event_text() called')
    
    parameters = []

    parameters.append({
        'input_1': None,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    container_url = phantom.build_phantom_rest_url('/container/{}'.format(container['id']))
    artifact_url = phantom.build_phantom_rest_url('/container/{}/artifacts'.format(container['id']))
                                                   
    container_and_artifacts = phantom.requests.get(container_url, verify=False).text + phantom.requests.get(artifact_url, verify=False).text
    parameters[0]['input_1'] = container_and_artifacts

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/passthrough", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/passthrough', parameters=parameters, name='get_full_event_text', callback=extract_email_domains)

    return

"""
Proceed for all domains that are not known to be safe.
"""
def extracted_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extracted_non_malicious() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["email_domain_rep:action_result.data.*.status_desc", "!=", "NON MALICIOUS"],
        ],
        name="extracted_non_malicious:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_email_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Construct a note with the domain reputation results.
"""
def format_email_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email_note() called')
    
    template = """The following domains were extracted from email addresses in the event and queried in Cisco Umbrella Investigate:

| Domain | Status | Risk Score | Category |
|---|---|---|---|
%%
| {0} | {1} | {2} | {3} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:extracted_non_malicious:condition_1:email_domain_rep:action_result.parameter.domain",
        "filtered-data:extracted_non_malicious:condition_1:email_domain_rep:action_result.data.*.status_desc",
        "filtered-data:extracted_non_malicious:condition_1:email_domain_rep:action_result.data.*.risk_score",
        "filtered-data:extracted_non_malicious:condition_1:email_domain_rep:action_result.data.*.category",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_note", separator=", ")

    add_email_note(container=container)

    return

"""
Proceed for all domains that are not known to be safe.
"""
def artifact_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifact_non_malicious() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact_domain_rep:action_result.data.*.status_desc", "!=", "NON MALICIOUS"],
        ],
        name="artifact_non_malicious:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_artifact_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Construct a note with the domain reputation results.
"""
def format_artifact_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_artifact_note() called')
    
    template = """The following domains were present in artifacts in the event and queried in Cisco Umbrella Investigate:

| Domain | Status | Risk Score | Category |
|---|---|---|---|
%%
| {0} | {1} | {2} | {3} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:artifact_non_malicious:condition_1:artifact_domain_rep:action_result.parameter.domain",
        "filtered-data:artifact_non_malicious:condition_1:artifact_domain_rep:action_result.data.*.status_desc",
        "filtered-data:artifact_non_malicious:condition_1:artifact_domain_rep:action_result.data.*.risk_score",
        "filtered-data:artifact_non_malicious:condition_1:artifact_domain_rep:action_result.data.*.category",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_artifact_note", separator=", ")

    add_artifact_note(container=container)

    return

"""
Post the note to the container.
"""
def add_artifact_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_artifact_note() called')

    formatted_data_1 = phantom.get_format_data(name='format_artifact_note')

    note_title = "Domain reputations from extracted email domains"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Post the note to the container.
"""
def add_email_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_email_note() called')

    formatted_data_1 = phantom.get_format_data(name='format_email_note')

    note_title = "Domain reputations from email addresses"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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