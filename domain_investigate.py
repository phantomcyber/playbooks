"""
Investigate a domain name (typically a top-level domain plus one). This playbook uses three different apps to run &quot;domain reputation&quot; and then aggregates the results and returns a note and a verdict.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'google_safe_browsing_reputation' block
    google_safe_browsing_reputation(container=container)
    # call 'cisco_umbrella_reputation' block
    cisco_umbrella_reputation(container=container)
    # call 'virustotal_reputation' block
    virustotal_reputation(container=container)

    return

def google_safe_browsing_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("google_safe_browsing_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_domain = phantom.collect2(container=container, datapath=["playbook_input:domain"])

    parameters = []

    # build parameters list for 'google_safe_browsing_reputation' call
    for playbook_input_domain_item in playbook_input_domain:
        if playbook_input_domain_item[0] is not None:
            parameters.append({
                "domain": playbook_input_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="google_safe_browsing_reputation", assets=["safe browsing"], callback=join_filter_matching_domains)

    return


def format_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_note() called")

    template = """| Domain | VirusTotal | Cisco Umbrella Investigate |\n|---|---|---|\n%%\n| {0} | {1} | {2} | \n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_matching_domains:condition_1:virustotal_reputation:action_result.parameter.domain",
        "filtered-data:filter_matching_domains:condition_1:virustotal_reputation:action_result.message",
        "filtered-data:filter_matching_domains:condition_1:cisco_umbrella_reputation:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_note")

    add_note_3(container=container)

    return


def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_3() called")

    format_note = phantom.get_format_data(name="format_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_note, note_format="markdown", note_type="general", title="Domain Investigate Results")

    verdict_decision(container=container)

    return


def cisco_umbrella_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("cisco_umbrella_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_domain = phantom.collect2(container=container, datapath=["playbook_input:domain"])

    parameters = []

    # build parameters list for 'cisco_umbrella_reputation' call
    for playbook_input_domain_item in playbook_input_domain:
        if playbook_input_domain_item[0] is not None:
            parameters.append({
                "domain": playbook_input_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="cisco_umbrella_reputation", assets=["ciscoumbrellainvestigate"], callback=join_filter_matching_domains)

    return


def verdict_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("verdict_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["filtered-data:filter_matching_domains:condition_1:cisco_umbrella_reputation:action_result.data.*.risk_score", ">", 25],
            ["filtered-data:filter_matching_domains:condition_1:virustotal_reputation:action_result.summary.malicious", ">=", 3]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        high_risk_verdict(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    low_risk_verdict(action=action, success=success, container=container, results=results, handle=handle)

    return


def high_risk_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("high_risk_verdict() called")

    template = """high_risk"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="high_risk_verdict")

    join_verdict_merge(container=container)

    return


def low_risk_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("low_risk_verdict() called")

    template = """low_risk"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="low_risk_verdict")

    join_verdict_merge(container=container)

    return


def join_verdict_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_verdict_merge() called")

    if phantom.completed(action_names=["google_safe_browsing_reputation", "cisco_umbrella_reputation", "virustotal_reputation"]):
        # call connected block "verdict_merge"
        verdict_merge(container=container, handle=handle)

    return


def verdict_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("verdict_merge() called")

    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "high_risk_verdict:formatted_data",
        "low_risk_verdict:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="verdict_merge", drop_none=True)

    return


def virustotal_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("virustotal_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_domain = phantom.collect2(container=container, datapath=["playbook_input:domain"])

    parameters = []

    # build parameters list for 'virustotal_reputation' call
    for playbook_input_domain_item in playbook_input_domain:
        if playbook_input_domain_item[0] is not None:
            parameters.append({
                "domain": playbook_input_domain_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="virustotal_reputation", assets=["virustotalv3"], callback=join_filter_matching_domains)

    return


def join_filter_matching_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_filter_matching_domains() called")

    if phantom.completed(action_names=["google_safe_browsing_reputation", "cisco_umbrella_reputation", "virustotal_reputation"]):
        # call connected block "filter_matching_domains"
        filter_matching_domains(container=container, handle=handle)

    return


def filter_matching_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_matching_domains() called")

    ################################################################################
    # Match together action results
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["virustotal_reputation:action_result.parameter.domain", "==", "cisco_umbrella_reputation:action_result.parameter.domain"]
        ],
        name="filter_matching_domains:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    verdict_merge = phantom.get_format_data(name="verdict_merge")

    output = {
        "verdict": verdict_merge,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return