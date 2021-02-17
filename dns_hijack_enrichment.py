"""
This Playbook is part of the Splunk Analytic Story called DNS Hijacking. It is made to be run when the Detection Search within that story called "DNS Record Changed" is used to identify DNS record changes for cloud and corporate domains used in your environment. The detection search is dependent on a support searched called "Discover DNS Records" which finds the common DNS responses for the last 30 days of monitored corporate domains and cloud providers (located in lookups: cim_corporate_email_domains.csv, cim_corporate_web_domains.csv, and cloud_domains.csv from Splunk CIM App). These responses are stored under the lookup called discovered_dns_records.csv. The playbook starts with the changed DNS records and uses MaxMind, whois, Censys, Malware Domain List, and PassiveTotal to gather attributes of the DNS records for comparison against expected values. The resulting enrichment is displayed in Mission Control and posted back to the Notable Event in Splunk ES.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_current_answer' block
    filter_current_answer(container=container)

    # call 'filter_query' block
    filter_query(container=container)

    return

"""
Filter down to artifacts with the domain name of the DNS query in Splunk
"""
def filter_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_query() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.query", "!=", ""],
        ],
        name="filter_query:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        domain_reputation_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
WHOIS lookup on the IP address
"""
def whois_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip:action_result.parameter.ip', 'geolocate_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], callback=whois_ip_callback, name="whois_ip", parent_action=action)

    return

def whois_ip_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('whois_ip_callback() called')
    
    censys_lookup_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_reputation_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add all the of the enrichment data as a comment to Mission Control 
"""
def add_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment() called')

    formatted_data_1 = phantom.get_format_data(name='format_results')

    phantom.comment(container=container, comment=formatted_data_1)

    return

"""
Format a selection of the most relevant results from the executed enrichment queries for use in a comment on Mission Control
"""
def format_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_results() called')
    
    template = """GeoIP Results: {0}
Whois Information: {1}
SSL Certificate From IP Details
Issuer Common Name {2}
Issuer Country {3}
Issuer Org {4}
PassiveTotal IP Reputation: {5}

Is domain a known malware domain list: {6}
Passive Total Domain Reputation: {7}"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_ip:action_result.message",
        "whois_ip:action_result.message",
        "censys_lookup_ip:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.common_name",
        "censys_lookup_ip:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.country",
        "censys_lookup_ip:action_result.data.*.ports.443.https.tls.certificate.parsed.issuer.organization",
        "ip_reputation_2:action_result.message",
        "domain_reputation_1:action_result.summary.malicious",
        "domain_reputation_2:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_results")

    add_comment(container=container)
    format_notable_comment(container=container)

    return

def join_format_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_results() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['lookup_certificate_1', 'ip_reputation_2', 'domain_reputation_1', 'domain_reputation_2']):
        
        # call connected block "format_results"
        format_results(container=container, handle=handle)
    
    return

"""
Gather domain reputation information from PassiveTotal
"""
def domain_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_2() called')

    # collect data for 'domain_reputation_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_query:condition_1:artifact:*.cef.query', 'filtered-data:filter_query:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ph': "",
                'to': "",
                'from': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['passivetotal'], callback=join_format_results, name="domain_reputation_2")

    return

"""
Gather domain reputation information from Malware Domain List
"""
def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_query:condition_1:artifact:*.cef.query', 'filtered-data:filter_query:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                'include_inactive': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['malware_domain_list'], callback=join_format_results, name="domain_reputation_1")

    return

"""
Gather reputation information about the IP from PassiveTotal
"""
def ip_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip:action_result.parameter.ip', 'geolocate_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'ph': "",
                'to': "",
                'from': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], callback=join_format_results, name="ip_reputation_2", parent_action=action)

    return

"""
Geolocate the IP address using MaxMind
"""
def geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip() called')

    # collect data for 'geolocate_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.current_answer', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=whois_ip, name="geolocate_ip")

    return

"""
Filter down to artifacts with the current answer of the DNS request as seen in Splunk
"""
def filter_current_answer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_current_answer() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.current_answer", "!=", ""],
        ],
        name="filter_current_answer:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        geolocate_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Censys lookup of the IP address to get the TLS certificate and other information
"""
def censys_lookup_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('censys_lookup_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'censys_lookup_ip' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip:action_result.parameter.ip', 'geolocate_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'censys_lookup_ip' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['censys'], callback=filter_tls_certificate, name="censys_lookup_ip", parent_action=action)

    return

"""
Gather the issuer and other information about the detected TLS certificates
"""
def lookup_certificate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_certificate_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_certificate_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_tls_certificate:condition_1:censys_lookup_ip:action_result.data.*.ports.443.https.tls.certificate.parsed.fingerprint_sha256", "filtered-data:filter_tls_certificate:condition_1:censys_lookup_ip:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'lookup_certificate_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'sha256': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="lookup certificate", parameters=parameters, assets=['censys'], callback=join_format_results, name="lookup_certificate_1")

    return

"""
Filter down to Censys results with TLS certificates on port 443
"""
def filter_tls_certificate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_tls_certificate() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["censys_lookup_ip:action_result.data.*.ports.443.https.tls.certificate.parsed.fingerprint_sha256", "!=", ""],
        ],
        name="filter_tls_certificate:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_certificate_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format a selection of the most relevant results from the executed enrichment queries for use in raising a notable event in Splunk 
"""
def format_notable_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_notable_comment() called')
    
    template = """Phantom gathered enrichment of this Notable Event, all of which can be viewed here: {0}

The most relevant fields from the enrichment are below:
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "format_results:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_notable_comment")

    update_notable_event(container=container)

    return

"""
Updating the notable event in Splunk with the enrichment data 
"""
def update_notable_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_notable_event() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_notable_event' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.event_id', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_notable_comment')

    parameters = []
    
    # build parameters list for 'update_notable_event' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'owner': "",
                'status': "",
                'comment': formatted_data_1,
                'urgency': "",
                'event_ids': container_item[0],
                'integer_status': "",
                'wait_for_confirmation': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update event", parameters=parameters, assets=['splunk_es'], name="update_notable_event")

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