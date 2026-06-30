"""
This playbook blocks malicious indicators extracted from a phishing analysis. It takes indicators from an &quot;SAA Indicators&quot; artifact and applies blocking actions across multiple security tools.\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "SAA Indicators"]
        ],
        conditions_dps=[
            ["artifact:*.name", "==", "SAA Indicators"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_indicators(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def parse_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("parse_indicators() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef"])

    filtered_artifact_0__cef = [item[0] for item in filtered_artifact_0_data_filter_1]

    parse_indicators__domain_list = None
    parse_indicators__ip_list = None
    parse_indicators__senderemail_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    indicator_artifact=filtered_artifact_0__cef[0]
    indicators=indicator_artifact.get("indicators")
    phantom.debug(indicators)
    
    #parse_indicators__file_list=indicators.get("hashes")
    #phantom.debug(parse_indicators__file_list)
    parse_indicators__ip_list=indicators.get("ips")
    phantom.debug(parse_indicators__ip_list)
    parse_indicators__domain_list=indicators.get("domains")
    phantom.debug(parse_indicators__domain_list)
    #parse_indicators__url_list=indicators.get("urls")
    #phantom.debug(parse_indicators__url_list)
    parse_indicators__senderemail_list=indicators.get("emails")
    phantom.debug(parse_indicators__senderemail_list)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="parse_indicators__inputs:0:filtered-data:filter_1:condition_1:artifact:*.cef", value=json.dumps(filtered_artifact_0__cef))

    phantom.save_block_result(key="parse_indicators:domain_list", value=json.dumps(parse_indicators__domain_list))
    phantom.save_block_result(key="parse_indicators:ip_list", value=json.dumps(parse_indicators__ip_list))
    phantom.save_block_result(key="parse_indicators:senderemail_list", value=json.dumps(parse_indicators__senderemail_list))

    phantom.save_block_result(key="parse_indicators_called", value="True")

    block_domain_1(container=container)
    block_ip_1(container=container)
    block_sender_email(container=container)

    return


@phantom.playbook_block()
def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_domain_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    domain_formatted_string = phantom.format(
        container=container,
        template="""%%\n{0}\n%%""",
        parameters=[
            "parse_indicators:custom_function:domain_list"
        ])

    parse_indicators__domain_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:domain_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if domain_formatted_string is not None:
        parameters.append({
            "domain": domain_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block domain", parameters=parameters, name="block_domain_1", assets=["cisco_umbrella"])

    return


@phantom.playbook_block()
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ip_formatted_string = phantom.format(
        container=container,
        template="""%%\n{0}\n%%""",
        parameters=[
            "parse_indicators:custom_function:ip_list"
        ])

    parse_indicators__ip_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:ip_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if ip_formatted_string is not None:
        parameters.append({
            "ip": ip_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block ip", parameters=parameters, name="block_ip_1", assets=["cisco_firepower"])

    return


@phantom.playbook_block()
def block_sender_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_sender_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    value_formatted_string = phantom.format(
        container=container,
        template="""%%\n{0}\n%%""",
        parameters=[
            "parse_indicators:custom_function:senderemail_list"
        ])

    parse_indicators__senderemail_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:senderemail_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if value_formatted_string is not None:
        parameters.append({
            "name": "BlockedSenders",
            "value": value_formatted_string,
            "commit_message": "Blocked Sender",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add dictionary item", parameters=parameters, name="block_sender_email", assets=["cisco_esa"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return