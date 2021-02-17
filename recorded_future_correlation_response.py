"""
This playbook responds to results from a Splunk correlation search by gathering more context about the relevant network indicators and blocking access to them if approved by an analyst. By comparing traffic monitoring data with Recorded Future bulk threat feeds, Splunk identifies high-risk network connection and forwards them to Phantom. Phantom queries Recorded Future for details about why the network indicators are on the threat list, and presents a decision to the analyst about whether the ip addresses and domain names should be blocked. In the is example, Layer 4 Traffic Monitoring by Cisco WSA is used as the network monitoring data source, and both Cisco Firepower NGFW and Cisco Umbrella can be used to enforce blocking actions at the perimeter and using DNS sinkholes.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'rule_name_decision' block
    rule_name_decision(container=container)

    return

"""
Gather all known threat intelligence about the IP from Recorded Future
"""
def ip_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_intelligence_1() called')

    deduplicate_inputs__ip = json.loads(phantom.get_run_data(key='deduplicate_inputs:ip'))
    # collect data for 'ip_intelligence_1' call

    parameters = []
    
    # build parameters list for 'ip_intelligence_1' call
    parameters.append({
        'ip': deduplicate_inputs__ip,
    })

    phantom.act(action="ip intelligence", parameters=parameters, assets=['recorded_future'], callback=join_format_prompt_question, name="ip_intelligence_1")

    return

"""
Gather all known threat intelligence about the domain from Recorded Future
"""
def domain_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_intelligence_1() called')

    deduplicate_inputs__domain = json.loads(phantom.get_run_data(key='deduplicate_inputs:domain'))
    # collect data for 'domain_intelligence_1' call

    parameters = []
    
    # build parameters list for 'domain_intelligence_1' call
    parameters.append({
        'domain': deduplicate_inputs__domain,
    })

    phantom.act(action="domain intelligence", parameters=parameters, assets=['recorded_future'], callback=join_format_prompt_question, name="domain_intelligence_1")

    return

"""
Only continue the playbook if this event was created by the appropriate Splunk correlation search
"""
def rule_name_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('rule_name_decision() called')
    
    name_param = container.get('name', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [name_param, "==", "Threat - Cisco WSA L4TM Correlation Against Recorded Future IP Threat List - Rule"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        deduplicate_inputs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Each matching Recorded Future threat rule will create a nearly identical artifact, so deduplicate these artifacts by just extracting the IP and domain name from the first artifact
"""
def deduplicate_inputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deduplicate_inputs() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.cef.dest_domain', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]

    deduplicate_inputs__ip = None
    deduplicate_inputs__domain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    deduplicate_inputs__ip = container_item_0[0]
    deduplicate_inputs__domain = container_item_1[0]
    
    if not deduplicate_inputs__ip or not deduplicate_inputs__domain:
        failure_message = "stopping the playbook because either the IP address or domain name was missing from the event"
        phantom.comment(container=container, comment=failure_message)
        phantom.error(failure_message)
        exit(1)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='deduplicate_inputs:ip', value=json.dumps(deduplicate_inputs__ip))
    phantom.save_run_data(key='deduplicate_inputs:domain', value=json.dumps(deduplicate_inputs__domain))
    ip_intelligence_1(container=container)
    domain_intelligence_1(container=container)

    return

"""
Use the source data and the threat context to build the prompt text asking the analyst whether or not to block the IP and domain
"""
def format_prompt_question(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_prompt_question() called')
    
    template = """A Splunk correlation search ({0}) detected an internal system opening a network connection to a potentially malicious IP address based on traffic monitoring from Cisco WSA and threat intelligence from Recorded Future:

IP address: {1}
Recorded Future Intel Card for IP address: {2}

Associated domain name: {3}
Recorded Future Intel Card for domain: {4}

Should Phantom use Cisco Firepower to block connections to that IP address and use Cisco Umbrella to block DNS resolutions of that domain?"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "deduplicate_inputs:custom_function:ip",
        "ip_intelligence_1:action_result.data.*.intelCard",
        "deduplicate_inputs:custom_function:domain",
        "domain_intelligence_1:action_result.data.*.intelCard",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt_question")

    block_recorded_future_ip_and_domain(container=container)

    return

def join_format_prompt_question(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_prompt_question() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['ip_intelligence_1', 'domain_intelligence_1']):
        
        # call connected block "format_prompt_question"
        format_prompt_question(container=container, handle=handle)
    
    return

"""
Send the prompt to block the playbook until a response is received
"""
def block_recorded_future_ip_and_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_recorded_future_ip_and_domain() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_prompt_question:formatted_data",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="block_recorded_future_ip_and_domain", parameters=parameters, response_types=response_types, callback=decide_prompt_response)

    return

"""
Determine the next action based on the analyst's response
"""
def decide_prompt_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decide_prompt_response() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["block_recorded_future_ip_and_domain:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    no_block_add_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Leave a comment so it is clear that the analyst chose not to block
"""
def no_block_add_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_block_add_comment() called')

    phantom.comment(container=container, comment="Analyst chose not to continue with blocking IP and domain")

    return

"""
Block all of the IP addresses in the deduplicated list by adjusting the firewall policy
"""
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    deduplicate_inputs__ip = json.loads(phantom.get_run_data(key='deduplicate_inputs:ip'))
    # collect data for 'block_ip_1' call

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    parameters.append({
        'ip': deduplicate_inputs__ip,
    })

    phantom.act(action="block ip", parameters=parameters, assets=['cisco_firepower'], name="block_ip_1")

    return

"""
Block all of the domain names in the deduplicated list using a DNS sinkhole
"""
def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    deduplicate_inputs__domain = json.loads(phantom.get_run_data(key='deduplicate_inputs:domain'))
    # collect data for 'block_domain_1' call

    parameters = []
    
    # build parameters list for 'block_domain_1' call
    parameters.append({
        'domain': deduplicate_inputs__domain,
        'disable_safeguards': False,
    })

    phantom.act(action="block domain", parameters=parameters, assets=['opendns_umbrella'], name="block_domain_1")

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