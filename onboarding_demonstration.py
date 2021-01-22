"""
Conduct enrichment on any URL's, IP addresses, and/or domain names in the event. Use the results to add context by updating the heads-up display and changing the severity of the event. This Playbook can be updated as needed to provide further enrichment, automate collaboration by sending emails, chat messages, or service tickets, or even to respond automatically to the event with a containment or correction action.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'whois_ip_1' block
    whois_ip_1(container=container)

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    # call 'lookup_ip_1' block
    lookup_ip_1(container=container)

    # call 'lookup_domain_2' block
    lookup_domain_2(container=container)

    return

"""
Pin the verified phishing URL's to the Phantom Heads-Up Display in Mission Control to increase their visibility
"""
def phishtank_pin_to_hud(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('phishtank_pin_to_hud() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:phishtank_filter:condition_1:url_reputation_1:action_result.parameter.url'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_0, message="PhishTank-verified phishing url", pin_type="card", pin_style="red", name=None)

    return

"""
Query the PhishTank database for reports of verified phishing campaigns using the URL
"""
def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['phishtank'], callback=phishtank_filter, name="url_reputation_1")

    return

"""
Filter down to only URL's that are in the database, valid, and verified
"""
def phishtank_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('phishtank_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.In Database", "==", True],
            ["url_reputation_1:action_result.summary.Valid", "==", True],
            ["url_reputation_1:action_result.summary.Verified", "==", True],
        ],
        logical_operator='and',
        name="phishtank_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        phishtank_pin_to_hud(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        raise_event_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Raise the Severity of this event in Phantom because the URL(s) were labelled as malicious  according to PhishTank
"""
def raise_event_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('raise_event_severity() called')

    phantom.set_severity(container=container, severity="high")

    return

"""
Use DNS to resolve the domain name to an IP address
"""
def lookup_domain_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_domain_2() called')

    # collect data for 'lookup_domain_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_domain_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'type': "",
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="lookup domain", parameters=parameters, assets=['google_dns'], name="lookup_domain_2")

    return

"""
Use a reverse DNS query to resolve the IP address to a domain name
"""
def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_ip_1() called')

    # collect data for 'lookup_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], name="lookup_ip_1")

    return

"""
Use the built-in Maxmind database to find the geographic location of the IP address
"""
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], name="geolocate_ip_1")

    return

"""
Use the whois information service to gather basic registration information about the IP address
"""
def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_ip_1() called')

    # collect data for 'whois_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], name="whois_ip_1")

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