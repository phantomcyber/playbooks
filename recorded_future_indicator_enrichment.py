"""
Enriches ingested events that contain file hashes, IP addresses, domain names, or URLs in some of the most common fields. This enrichment pulls a variety of threat intelligence details from Recorded Future into the investigation, allowing further analysis and contextual actions.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

def extract_domain_from_url(url):
    try:
        domain = url.split('://', 1)[1].split('/', 1)[0]
    except:
        return None
    return domain

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_hash_and_ip' block
    filter_hash_and_ip(container=container)

    # call 'filter_domain_and_url' block
    filter_domain_and_url(container=container)

    return

"""
Filter common file hash and ip address fields
"""
def filter_hash_and_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_hash_and_ip() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        name="filter_hash_and_ip:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_intel_source_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_hash_and_ip:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        ip_intel_destination_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_hash_and_ip:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        file_intelligence_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

"""
Filter the common domain name and URL fields
"""
def filter_domain_and_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_domain_and_url() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_domain_and_url:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_intel_dest_dns(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_domain_and_url:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        url_intelligence_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
        ],
        name="filter_domain_and_url:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        domain_intel_source_dns(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

"""
Gather threat intelligence about source IP addresses in the event
"""
def ip_intel_source_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_intel_source_address() called')

    # collect data for 'ip_intel_source_address' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_hash_and_ip:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_hash_and_ip:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_intel_source_address' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip intelligence", parameters=parameters, assets=['recorded_future'], name="ip_intel_source_address")

    return

"""
Gather threat intelligence about destination IP addresses in the event
"""
def ip_intel_destination_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_intel_destination_address() called')

    # collect data for 'ip_intel_destination_address' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_hash_and_ip:condition_2:artifact:*.cef.destinationAddress', 'filtered-data:filter_hash_and_ip:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_intel_destination_address' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip intelligence", parameters=parameters, assets=['recorded_future'], name="ip_intel_destination_address")

    return

"""
Gather threat intelligence about file hashes in the event
"""
def file_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_intelligence_1() called')

    # collect data for 'file_intelligence_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_hash_and_ip:condition_3:artifact:*.cef.fileHash', 'filtered-data:filter_hash_and_ip:condition_3:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_intelligence_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file intelligence", parameters=parameters, assets=['recorded_future'], name="file_intelligence_1")

    return

"""
Gather threat intelligence about source domain names in the event
"""
def domain_intel_source_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_intel_source_dns() called')

    # collect data for 'domain_intel_source_dns' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_domain_and_url:condition_3:artifact:*.cef.sourceDnsDomain', 'filtered-data:filter_domain_and_url:condition_3:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_intel_source_dns' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain intelligence", parameters=parameters, assets=['recorded_future'], name="domain_intel_source_dns")

    return

"""
Gather threat intelligence about destination domain names in the event
"""
def domain_intel_dest_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_intel_dest_dns() called')

    # collect data for 'domain_intel_dest_dns' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_domain_and_url:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_domain_and_url:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_intel_dest_dns' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain intelligence", parameters=parameters, assets=['recorded_future'], name="domain_intel_dest_dns")

    return

"""
Gather threat intelligence about URLs in the event
"""
def url_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_intelligence_1() called')

    # collect data for 'url_intelligence_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_domain_and_url:condition_2:artifact:*.cef.requestURL', 'filtered-data:filter_domain_and_url:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_intelligence_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url intelligence", parameters=parameters, assets=['recorded_future'], name="url_intelligence_1")

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