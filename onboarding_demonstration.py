"""
Conduct enrichment on the URL, file hash, IP address, and/or domain name in the event. Use the results to add context by updating the heads-up display and changing the severity of the event. This Playbook can be updated as needed to provide further enrichment, automate collaboration by sending emails, chat messages, or service tickets, or even to respond automatically to the event with a containment or correction action.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'whois_ip_1' block
    whois_ip_1(container=container)

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    # call 'lookup_domain_1' block
    lookup_domain_1(container=container)

    return

"""
Filter down to only URL's that are in the database, valid, and verified
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

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
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        phishtank_pin_to_hud(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter down to only file hashes that are tagged as "malware" according to Cymon
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.results.*.tag", "==", "malware"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cymon_pin_to_hud(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Pin the verified phishing URL's to the Phantom Heads-Up Display in Mission Control to increase their visibility
"""
def phishtank_pin_to_hud(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('phishtank_pin_to_hud() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:url_reputation_1:action_result.parameter.url"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, message="PhishTank-verified phishing url", data=filtered_results_item_1_0, pin_type="card_large", pin_style="red")
    join_decision_1(container=container)

    return

"""
Pin the malware file hashes to the Phantom Heads-Up Display in Mission Control to increase their visibility
"""
def cymon_pin_to_hud(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('cymon_pin_to_hud() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:file_reputation_1:action_result.data.*.results.*.title", "filtered-data:filter_2:condition_1:file_reputation_1:action_result.parameter.hash"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_1_1 = [item[1] for item in filtered_results_data_1]

    phantom.pin(container=container, message=filtered_results_item_1_0, data=filtered_results_item_1_1, pin_type="card_large", pin_style="red")
    join_decision_1(container=container)

    return

"""
Raise the event severity based on the bad reputation of the IP address
"""
def ip_rep_raise_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_rep_raise_severity() called')

    phantom.set_severity(container, "high")

    return

"""
Raise the event severity based on the bad reputation of the URL
"""
def url_rep_raise_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_rep_raise_severity() called')

    phantom.set_severity(container, "high")

    return

"""
Raise the event severity based on the bad reputation of the file hash
"""
def file_rep_raise_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_rep_raise_severity() called')

    phantom.set_severity(container, "high")

    return

"""
Decide based on the results of the reputation queries whether or not to raise the severity of the event
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.In Database", "==", True],
            ["url_reputation_1:action_result.summary.Valid", "==", True],
            ["url_reputation_1:action_result.summary.Verified", "==", True],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        url_rep_raise_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.results.*.tag", "==", "malware"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        file_rep_raise_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.data.*.events.results.*.tag", "==", "dnsbl"],
            ["ip_reputation_1:action_result.data.*.events.results.*.tag", "==", "malicious activity"],
        ],
        logical_operator='or')

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        ip_rep_raise_severity(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def join_decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_decision_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'url_reputation_1', 'file_reputation_1', 'ip_reputation_1', 'geolocate_ip_1', 'whois_ip_1', 'lookup_domain_1' ]):
        
        # call connected block "decision_1"
        decision_1(container=container, handle=handle)
    
    return

"""
Gather passive DNS lookups of the domain using the Cymon.io open source intelligence database
"""
def lookup_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('lookup_domain_1() called')

    # collect data for 'lookup_domain_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_domain_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("lookup domain", parameters=parameters, assets=['cymon'], callback=join_decision_1, name="lookup_domain_1")

    return

"""
Use the whois information service to gather basic registration information about the IP address
"""
def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    phantom.act("whois ip", parameters=parameters, assets=['whois'], callback=join_decision_1, name="whois_ip_1")

    return

"""
Use the built-in Maxmind database to find the geographic location of the IP address
"""
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_decision_1, name="geolocate_ip_1")

    return

"""
Query the reputation of the IP address in the Cymon.io open source intelligence database
"""
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['cymon'], callback=join_decision_1, name="ip_reputation_1")

    return

"""
Query the reputation of the file hash in the Cymon.io open source intelligence database
"""
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['cymon'], callback=filter_2, name="file_reputation_1")

    return

"""
Query the PhishTank database for reports of verified phishing campaigns using the URL
"""
def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
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

    phantom.act("url reputation", parameters=parameters, assets=['phishtank'], callback=filter_1, name="url_reputation_1")

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