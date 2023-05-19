"""
Enriches ingested events that contain file hashes, IP addresses, domain names, or URLs in some of the most common fields. This enrichment pulls a variety of threat intelligence details from Recorded Future into the investigation, allowing further analysis and contextual actions.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_hash_and_ip' block
    filter_hash_and_ip(container=container)
    # call 'filter_domain_and_url' block
    filter_domain_and_url(container=container)

    return

def filter_hash_and_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_hash_and_ip() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""]
        ],
        name="filter_hash_and_ip:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_intel_source_address(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""]
        ],
        name="filter_hash_and_ip:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        ip_intel_destination_address(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="filter_hash_and_ip:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        file_intelligence(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


def filter_domain_and_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_domain_and_url() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        name="filter_domain_and_url:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_intel_destination_dns(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_domain_and_url:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        url_intelligence(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""]
        ],
        name="filter_domain_and_url:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        domain_intel_source_dns(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


def ip_intel_destination_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_intel_destination_address() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about destination IP addresses in the event
    ################################################################################

    filtered_artifact_0_data_filter_hash_and_ip = phantom.collect2(container=container, datapath=["filtered-data:filter_hash_and_ip:condition_2:artifact:*.cef.destinationAddress"])

    parameters = []

    # build parameters list for 'ip_intel_destination_address' call
    for filtered_artifact_0_item_filter_hash_and_ip in filtered_artifact_0_data_filter_hash_and_ip:
        if filtered_artifact_0_item_filter_hash_and_ip[0] is not None:
            parameters.append({
                "ip": filtered_artifact_0_item_filter_hash_and_ip[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip intelligence", parameters=parameters, name="ip_intel_destination_address", assets=["recorded future"])

    return


def ip_intel_source_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_intel_source_address() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about source IP addresses in the event
    ################################################################################

    filtered_artifact_0_data_filter_hash_and_ip = phantom.collect2(container=container, datapath=["filtered-data:filter_hash_and_ip:condition_1:artifact:*.cef.sourceAddress"])

    parameters = []

    # build parameters list for 'ip_intel_source_address' call
    for filtered_artifact_0_item_filter_hash_and_ip in filtered_artifact_0_data_filter_hash_and_ip:
        if filtered_artifact_0_item_filter_hash_and_ip[0] is not None:
            parameters.append({
                "ip": filtered_artifact_0_item_filter_hash_and_ip[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip intelligence", parameters=parameters, name="ip_intel_source_address", assets=["recorded future"])

    return


def file_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_intelligence() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about file hashes in the event
    ################################################################################

    filtered_artifact_0_data_filter_hash_and_ip = phantom.collect2(container=container, datapath=["filtered-data:filter_hash_and_ip:condition_3:artifact:*.cef.fileHash"])

    parameters = []

    # build parameters list for 'file_intelligence' call
    for filtered_artifact_0_item_filter_hash_and_ip in filtered_artifact_0_data_filter_hash_and_ip:
        if filtered_artifact_0_item_filter_hash_and_ip[0] is not None:
            parameters.append({
                "hash": filtered_artifact_0_item_filter_hash_and_ip[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file intelligence", parameters=parameters, name="file_intelligence", assets=["recorded future"])

    return


def domain_intel_destination_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_intel_destination_dns() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about destination domain names in the event
    ################################################################################

    filtered_artifact_0_data_filter_domain_and_url = phantom.collect2(container=container, datapath=["filtered-data:filter_domain_and_url:condition_1:artifact:*.cef.destinationDnsDomain"])

    parameters = []

    # build parameters list for 'domain_intel_destination_dns' call
    for filtered_artifact_0_item_filter_domain_and_url in filtered_artifact_0_data_filter_domain_and_url:
        if filtered_artifact_0_item_filter_domain_and_url[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_filter_domain_and_url[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain intelligence", parameters=parameters, name="domain_intel_destination_dns", assets=["recorded future"])

    return


def url_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_intelligence() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about URLs in the event
    ################################################################################

    filtered_artifact_0_data_filter_domain_and_url = phantom.collect2(container=container, datapath=["filtered-data:filter_domain_and_url:condition_2:artifact:*.cef.requestURL"])

    parameters = []

    # build parameters list for 'url_intelligence' call
    for filtered_artifact_0_item_filter_domain_and_url in filtered_artifact_0_data_filter_domain_and_url:
        if filtered_artifact_0_item_filter_domain_and_url[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_domain_and_url[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url intelligence", parameters=parameters, name="url_intelligence", assets=["recorded future"])

    return


def domain_intel_source_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_intel_source_dns() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather threat intelligence about source domain names in the event
    ################################################################################

    filtered_artifact_0_data_filter_domain_and_url = phantom.collect2(container=container, datapath=["filtered-data:filter_domain_and_url:condition_3:artifact:*.cef.sourceDnsDomain"])

    parameters = []

    # build parameters list for 'domain_intel_source_dns' call
    for filtered_artifact_0_item_filter_domain_and_url in filtered_artifact_0_data_filter_domain_and_url:
        if filtered_artifact_0_item_filter_domain_and_url[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_filter_domain_and_url[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain intelligence", parameters=parameters, name="domain_intel_source_dns", assets=["recorded future"])

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return