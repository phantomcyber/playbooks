"""
Enriches ingested events that contain IP addresses or domain names. This enrichment includes resolving domain names to IP addresses using DNS, geolocating IP addresses using Maxmind, gathering registration information using WHOIS, and checking a Custom List within Phantom to determine whether the IP addresses are in the internal network ranges.
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
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    return

"""
Add a comment to Mission Control to summarize the lookups and the internal address checks.
"""
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_2() called')

    formatted_data_1 = phantom.get_format_data(name='check_internal_addresses')

    phantom.comment(container=container, comment=formatted_data_1)

    return

"""
Summarize the action results for the DNS, geolocation, and WHOIS lookups. The formatted string will be added as a comment in Mission Control.
"""
def summarize_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('summarize_results() called')
    
    template = ""
    # collect the status of every DNS, geolocate, and WHOIS query
    dns_datapaths = [
        "lookup_source_domain:action_result.status",
        "lookup_dest_domain:action_result.status",
        "lookup_ip_for_url:action_result.status"
    ]
    dns_statuses = [phantom.collect2(container=container, datapath=[datapath], action_results=results) for datapath in dns_datapaths]
    attempts = successes = 0
    for block in dns_statuses:
        for action in block:
            attempts += 1
            if action[0] == "success":
                successes += 1
    template += "{} out of {} attempted DNS queries were successful\n".format(successes, attempts)
            
    geolocate_datapaths = [
        "geolocate_ip_dst:action_result.status",
        "geolocate_ip_src:action_result.status",
        "geolocate_sourceAddress:action_result.status",
        "geolocate_destAddress:action_result.status",
        "geolocate_source:action_result.status",
        "geolocate_dest:action_result.status",
        "geolocate_url:action_result.status",
    ]
    geolocate_statuses = [phantom.collect2(container=container, datapath=[datapath], action_results=results) for datapath in geolocate_datapaths]
    attempts = successes = 0
    for block in geolocate_statuses:
        for action in block:
            attempts += 1
            if action[0] == "success":
                successes += 1
    template += "{} out of {} attempted geolocations were successful\n".format(successes, attempts)
    
    whois_datapaths = [
        "whois_ip_dst:action_result.status",
        "whois_ip_src:action_result.status",
        "whois_sourceAddress:action_result.status",
        "whois_destAddress:action_result.status",
        "whois_source_ip:action_result.status",
        "whois_dest_ip:action_result.status",
        "whois_url_ip:action_result.status",
    ]
    whois_statuses = [phantom.collect2(container=container, datapath=[datapath], action_results=results) for datapath in whois_datapaths]
    attempts = successes = 0
    for block in whois_statuses:
        for action in block:
            attempts += 1
            if action[0] == "success":
                successes += 1
    template += "{} out of {} attempted WHOIS queries were successful\n".format(successes, attempts)
        
    phantom.format(container=container, template=template, parameters=[], name="summarize_results")

    check_internal_addresses(container=container)

    return

def join_summarize_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_summarize_results() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['whois_ip_dst', 'whois_ip_src', 'whois_sourceAddress', 'whois_destAddress', 'whois_source_ip', 'whois_dest_ip', 'whois_url_ip']):
        
        # call connected block "summarize_results"
        summarize_results(container=container, handle=handle)
    
    return

"""
Condition 1:  Investigate artifacts where sourceAddress is not empty
Condition 2: Investigate artifacts where destinationAddress is not empty
Condition 3: Investigate artifacts where dst is not empty
Condition 4: Investigate artifacts where src is not empty
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        geolocate_sourceAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        geolocate_destAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.dst", "!=", ""],
        ],
        name="filter_1:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        geolocate_ip_dst(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.src", "!=", ""],
        ],
        name="filter_1:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        geolocate_ip_src(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

"""
Condition 1:  Investigate artifacts where destinationDnsDomain is not empty
Condition 2: Investigate artifacts where requestURL is not empty
Condition 3: Investigate artifacts where sourceDnsDomain is not empty
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_dest_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        lookup_ip_for_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
        ],
        name="filter_2:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        lookup_source_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

"""
Resolve cef.sourceDnsDomain to an IP address
"""
def lookup_source_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_source_domain() called')

    # collect data for 'lookup_source_domain' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_3:artifact:*.cef.sourceDnsDomain', 'filtered-data:filter_2:condition_3:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_source_domain' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'type': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="lookup domain", parameters=parameters, assets=['dns'], callback=geolocate_source, name="lookup_source_domain")

    return

"""
Resolve cef.destinationDnsDomain to an IP address
"""
def lookup_dest_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_dest_domain() called')

    # collect data for 'lookup_dest_domain' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_dest_domain' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'type': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="lookup domain", parameters=parameters, assets=['dns'], callback=geolocate_dest, name="lookup_dest_domain")

    return

"""
Extract the domain part of the URL and use DNS to resolve it to an IP address.
"""
def lookup_ip_for_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    phantom.debug('lookup_url() called')

    # collect data for 'lookup_url' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_2:artifact:*.cef.requestURL', 'filtered-data:filter_2:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_url' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': extract_domain_from_url(filtered_artifacts_item_1[0]),
                'type': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("lookup domain", parameters=parameters, assets=['dns'], callback=geolocate_url, name="lookup_ip_for_url")
    
    return

"""
Geolocate the IP address in cef.src using Maxmind
"""
def geolocate_ip_src(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_src() called')

    # collect data for 'geolocate_ip_src' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.src', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_src' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_ip_src, name="geolocate_ip_src")

    return

"""
Geolocate the IP address in cef.sourceAddress using Maxmind
"""
def geolocate_sourceAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_sourceAddress() called')

    # collect data for 'geolocate_sourceAddress' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_sourceAddress' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_sourceAddress, name="geolocate_sourceAddress")

    return

"""
WHOIS lookup on the IP address in cef.src
"""
def whois_ip_src(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip_src() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip_src' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_src:action_result.parameter.ip', 'geolocate_ip_src:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip_src' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_ip_src", parent_action=action)

    return

"""
WHOIS lookup on the IP address in cef.destinationAddress
"""
def whois_destAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_destAddress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_destAddress' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_destAddress:action_result.parameter.ip', 'geolocate_destAddress:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_destAddress' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_destAddress", parent_action=action)

    return

"""
Geolocate the IP address in cef.destinationAddress using Maxmind
"""
def geolocate_destAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_destAddress() called')

    # collect data for 'geolocate_destAddress' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_destAddress' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_destAddress, name="geolocate_destAddress")

    return

"""
Geolocate the resolved IP address using Maxmind
"""
def geolocate_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_source() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_source' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_source_domain:action_result.summary.record_info', 'lookup_source_domain:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_source' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_source_ip, name="geolocate_source", parent_action=action)

    return

"""
Geolocate the resolved IP address using Maxmind
"""
def geolocate_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_dest() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_dest' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_dest_domain:action_result.summary.record_info', 'lookup_dest_domain:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_dest' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_dest_ip, name="geolocate_dest", parent_action=action)

    return

"""
Geolocate the resolved IP address using Maxmind
"""
def geolocate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_url' call
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_ip_for_url:action_result.summary.record_info', 'lookup_ip_for_url:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'geolocate_url' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_url_ip, name="geolocate_url", parent_action=action)

    return

"""
WHOIS lookup on the IP address in cef.sourceAddress
"""
def whois_sourceAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_sourceAddress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_sourceAddress' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_sourceAddress:action_result.parameter.ip', 'geolocate_sourceAddress:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_sourceAddress' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_sourceAddress", parent_action=action)

    return

"""
WHOIS lookup on the resolved IP address
"""
def whois_source_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_source_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_source_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_source:action_result.parameter.ip', 'geolocate_source:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_source_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_source_ip", parent_action=action)

    return

"""
WHOIS lookup on the resolved IP address
"""
def whois_dest_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_dest_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_dest_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_dest:action_result.parameter.ip', 'geolocate_dest:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_dest_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_dest_ip", parent_action=action)

    return

"""
WHOIS lookup on the resolved IP address
"""
def whois_url_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_url_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_url_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_url:action_result.parameter.ip', 'geolocate_url:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_url_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_url_ip", parent_action=action)

    return

"""
Geolocate the IP address in cef.dst using Maxmind
"""
def geolocate_ip_dst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_dst() called')

    # collect data for 'geolocate_ip_dst' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.dst', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_dst' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_ip_dst, name="geolocate_ip_dst")

    return

"""
WHOIS lookup on the IP address in cef.dst
"""
def whois_ip_dst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip_dst() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip_dst' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_dst:action_result.parameter.ip', 'geolocate_ip_dst:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip_dst' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=join_summarize_results, name="whois_ip_dst", parent_action=action)

    return

"""
Check all identified IP addresses against the Custom List called "internal network ranges" if it exists. Format the output into a string for adding to a Mission Control comment.
"""
def check_internal_addresses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_internal_addresses() called')
    
    datapaths = [
        "geolocate_ip_dst:action_result.parameter.ip",
        "geolocate_ip_src:action_result.parameter.ip",
        "geolocate_sourceAddress:action_result.parameter.ip",
        "geolocate_destAddress:action_result.parameter.ip",
        "geolocate_source:action_result.parameter.ip",
        "geolocate_dest:action_result.parameter.ip",
        "geolocate_url:action_result.parameter.ip",
    ]

    ip_parameters = [phantom.collect2(container=container, datapath=[datapath], action_results=results) for datapath in datapaths]
    ip_addresses = []
    for block in ip_parameters:
        for action_run in block:
            ip_addresses += action_run

    success, message, internal_network_ranges = phantom.get_list(list_name='internal network ranges')
    if not success:
        check_internal_template = "Failed to check IP addresses against internal network because the Custom List 'internal network ranges' does not exist."
    else:
        check_internal_template = "Using the Custom List 'internal network ranges', the following internal IP addresses were identified:\n"
        internal_ip_addresses = []
        for row in internal_network_ranges:
            for ip_address in set(ip_addresses):
                if phantom.address_in_network(ip_address, str(row[0])):
                    internal_ip_addresses.append(ip_address)
                    check_internal_template += "{} is in internal network range {}\n".format(ip_address, row[0])
        for idx, external_address in enumerate(set(ip_addresses) - set(internal_ip_addresses)):
            if idx == 0:
                check_internal_template += "\nThe following IP addresses were not found in internal network ranges:\n"
            check_internal_template += external_address + '\n'

    template = "{0}\n\n" + check_internal_template
    parameters = [
        "summarize_results:formatted_data",
    ]
    phantom.format(container=container, template=template, parameters=parameters, name="check_internal_addresses")

    add_comment_2(container=container)

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