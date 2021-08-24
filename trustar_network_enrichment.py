"""
Gather threat intelligence information about IP addresses, domain names, and URLs from TruSTAR to enrich any event containing these indicators.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'collect_ip' block
    collect_ip(container=container)

    # call 'collect_url' block
    collect_url(container=container)

    # call 'collect_domain' block
    collect_domain(container=container)

    return

"""
Collect all IP addresses in the container.
"""
def collect_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_ip() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "ip",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'tags': None,
                'scope': None,
                'container': item0[0],
                'data_types': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/collect_by_cef_type", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/collect_by_cef_type', parameters=parameters, name='collect_ip', callback=ip_filter_none)

    return

"""
Collect threat information about the IP addresses in TruSTAR.
"""
def hunt_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_ip' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['collect_ip:custom_function_result.data.*.artifact_value'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_ip' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'ip': custom_function_results_item_1[0],
            })

    phantom.act(action="hunt ip", parameters=parameters, assets=['trustar'], callback=ip_report_check, name="hunt_ip")

    return

"""
Get the TruSTAR report.
"""
def get_ip_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ip_report() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_ip_report' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_ip:action_result.data.*.report_id', 'hunt_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_ip_report' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id_type': "",
                'report_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get report", parameters=parameters, assets=['trustar'], name="get_ip_report")

    return

"""
Collect all URLs in the container.
"""
def collect_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_url() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "url",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'tags': None,
                'scope': None,
                'container': item0[0],
                'data_types': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/collect_by_cef_type", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/collect_by_cef_type', parameters=parameters, name='collect_url', callback=url_filter_none)

    return

"""
Collect threat information about the URLs in TruSTAR.
"""
def hunt_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_url_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:url_filter_none:condition_1:collect_url:custom_function_result.data.*.artifact_value'])

    parameters = []
    
    # build parameters list for 'hunt_url_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'url': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="hunt url", parameters=parameters, assets=['trustar'], callback=url_report_check, name="hunt_url_1")

    return

"""
Collect all domain names in the container.
"""
def collect_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_domain() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "domain",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'tags': None,
                'scope': None,
                'container': item0[0],
                'data_types': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/collect_by_cef_type", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/collect_by_cef_type', parameters=parameters, name='collect_domain', callback=domain_filter_none)

    return

"""
Resolve the domain names to IP addresses using DNS.
"""
def lookup_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_domain_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:domain_filter_none:condition_1:collect_domain:custom_function_result.data.*.artifact_value'])

    parameters = []
    
    # build parameters list for 'lookup_domain_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'type': "",
                'domain': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="lookup domain", parameters=parameters, assets=['google_dns'], callback=hunt_resolved_ip, name="lookup_domain_1")

    return

"""
Collect threat information about the resolved IP addresses in TruSTAR.
"""
def hunt_resolved_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_resolved_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'hunt_resolved_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_domain_1:action_result.data.*.record_info_objects.*.record_info', 'lookup_domain_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'hunt_resolved_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="hunt ip", parameters=parameters, assets=['trustar'], callback=resolved_ip_report_check, name="hunt_resolved_ip", parent_action=action)

    return

"""
Get the TruSTAR report.
"""
def get_resolved_ip_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_resolved_ip_report() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_resolved_ip_report' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_resolved_ip:action_result.data.*.report_id', 'hunt_resolved_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_resolved_ip_report' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id_type': "",
                'report_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get report", parameters=parameters, assets=['trustar'], name="get_resolved_ip_report")

    return

"""
Get the TruSTAR report.
"""
def get_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_url_report() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_url_report' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_url_1:action_result.data.*.report_id', 'hunt_url_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_url_report' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id_type': "",
                'report_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get report", parameters=parameters, assets=['trustar'], name="get_url_report")

    return

"""
Filter out nonexistent domain names.
"""
def domain_filter_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_filter_none() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["collect_domain:custom_function_result.data.*.artifact_value", "!=", ""],
        ],
        name="domain_filter_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter out nonexistent URLs.
"""
def url_filter_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_filter_none() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["collect_url:custom_function_result.data.*.artifact_value", "!=", ""],
        ],
        name="url_filter_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if there is a report.
"""
def resolved_ip_report_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('resolved_ip_report_check() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_resolved_ip:action_result.data.*.report_id", "!=", ""],
        ],
        name="resolved_ip_report_check:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_resolved_ip_report(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if there is a report.
"""
def ip_report_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_report_check() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_ip:action_result.data.*.report_id", "!=", ""],
        ],
        name="ip_report_check:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_ip_report(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if there is a report.
"""
def url_report_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_report_check() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_url_1:action_result.data.*.report_id", "!=", ""],
        ],
        name="url_report_check:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_url_report(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter out nonexistent IP addresses.
"""
def ip_filter_none(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_filter_none() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["collect_ip:custom_function_result.data.*.artifact_value", "!=", ""],
        ],
        name="ip_filter_none:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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