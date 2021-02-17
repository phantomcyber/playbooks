"""
This helper playbook uses an nmap scan to build a custom list of endpoints running an open service on TCP port 5900. This custom list will be used to enumerate MacOS High Sierra endpoints to respond to the 2017-11-28 disclosure of root user access without a password.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'scan_port_5900' block
    scan_port_5900(container=container)

    return

"""
Scan the given subnet with a TCP syn-ack on port 5900 to detect VNC or ARD services.
"""
def scan_port_5900(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('scan_port_5900() called')

    # collect data for 'scan_port_5900' call

    parameters = []
    
    # build parameters list for 'scan_port_5900' call
    parameters.append({
        'script': "",
        'portlist': 5900,
        'udp_scan': "",
        'ip_hostname': "198.51.100.*",
        'script-args': "",
    })

    phantom.act(action="scan network", parameters=parameters, assets=['nmap'], callback=filter_1, name="scan_port_5900")

    return

"""
Only pass on ip addresses that are found to have open ports.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["scan_port_5900:action_result.data.*.tcp.*.state", "==", "open"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_addresses_to_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Create a custom list with the given IP addresses or add to one if it exists.
"""
def add_addresses_to_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_addresses_to_list() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:scan_port_5900:action_result.data.*.addresses.ipv4.*.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.add_list("macos_endpoints", filtered_results_item_1_0)

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