"""
This playbook responds to Recorded Future monitoring of potential typosquatting domain alerts. The domain is filtered from the artifacts and enriched several times via Whois, Censys, Urlscan, DNS, and Recorded Future&#39;s Intelligence.\n\nThis playbook runs on the assumption that the typosquatting alert rule ID has been configured in the Recorded Future app&#39;s asset &#39;on-poll&#39; field.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_2' block
    filter_2(container=container)

    return

@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["DOMAIN", "in", "artifact:*.name"],
            ["artifact:*.cef.title", "==", "Certificate Registration"],
            ["artifact:*.cef.domain", "!=", ""]
        ],
        name="filter_2:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lookup_domain_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def lookup_domain_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("lookup_domain_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.domain","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'lookup_domain_2' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        if filtered_artifact_0_item_filter_2[0] is not None:
            parameters.append({
                "type": "A",
                "domain": filtered_artifact_0_item_filter_2[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup domain", parameters=parameters, name="lookup_domain_2", assets=["dns"], callback=lookup_domain_2_callback)

    return


@phantom.playbook_block()
def lookup_domain_2_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("lookup_domain_2_callback() called")

    
    filter_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    whois_domain_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def filter_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_domain() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["lookup_domain_2:action_result.summary.record_info", "!=", ""]
        ],
        name="filter_domain:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        whois_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_domain:condition_1:lookup_domain_2:action_result.summary.record_info"])

    parameters = []

    # build parameters list for 'whois_ip_1' call
    for filtered_result_0_item_filter_domain in filtered_result_0_data_filter_domain:
        if filtered_result_0_item_filter_domain[0] is not None:
            parameters.append({
                "ip": filtered_result_0_item_filter_domain[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois ip", parameters=parameters, name="whois_ip_1", assets=["whois"], callback=recorded_future_ip_intelligence)

    return


@phantom.playbook_block()
def recorded_future_ip_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("recorded_future_ip_intelligence() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_domain = phantom.collect2(container=container, datapath=["filtered-data:filter_domain:condition_1:lookup_domain_2:action_result.summary.record_info"])

    parameters = []

    # build parameters list for 'recorded_future_ip_intelligence' call
    for filtered_result_0_item_filter_domain in filtered_result_0_data_filter_domain:
        if filtered_result_0_item_filter_domain[0] is not None:
            parameters.append({
                "ip": filtered_result_0_item_filter_domain[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip intelligence", parameters=parameters, name="recorded_future_ip_intelligence", assets=["recorded future"])

    return


@phantom.playbook_block()
def whois_domain_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_domain_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.domain","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'whois_domain_2' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        if filtered_artifact_0_item_filter_2[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_filter_2[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois domain", parameters=parameters, name="whois_domain_2", assets=["whois"], callback=censys_query_certificate)

    return


@phantom.playbook_block()
def censys_query_certificate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("censys_query_certificate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.domain","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'censys_query_certificate' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        if filtered_artifact_0_item_filter_2[0] is not None:
            parameters.append({
                "limit": 200,
                "query": filtered_artifact_0_item_filter_2[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("query certificate", parameters=parameters, name="censys_query_certificate", assets=["censys"], callback=urlscan_detonate_url)

    return


@phantom.playbook_block()
def urlscan_detonate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("urlscan_detonate_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.domain","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'urlscan_detonate_url' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        if filtered_artifact_0_item_filter_2[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_2[0],
                "get_result": True,
                "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="urlscan_detonate_url", assets=["urlscan"], callback=recorded_future_domain_intelligence)

    return


@phantom.playbook_block()
def recorded_future_domain_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("recorded_future_domain_intelligence() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.domain","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'recorded_future_domain_intelligence' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        if filtered_artifact_0_item_filter_2[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_filter_2[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain intelligence", parameters=parameters, name="recorded_future_domain_intelligence", assets=["recorded future"])

    return


@phantom.playbook_block()
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