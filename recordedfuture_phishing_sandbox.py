"""
This playbook is designed to run on containers created from the EWS for Office 365 app&#39;s polling feature that monitors an email inbox, ingests emails, and creates artifacts based on those emails.\n\nThis playbook will extract files from the vault and create artifacts for each one. Then, the playbook will submit each file to Recorded Future&#39;s sandbox for analysis. \n\nThe same will be done for URLs for any artifact that contains a cef field of requestURL.\n\nThe results will be brought back into a container for analysis.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_files_from_vault' block
    get_files_from_vault(container=container)
    # call 'filter_urls' block
    filter_urls(container=container)

    return

@phantom.playbook_block()
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_file_artifacts = phantom.collect2(container=container, datapath=["filtered-data:filter_file_artifacts:condition_1:artifact:*.cef.vaultId","filtered-data:filter_file_artifacts:condition_1:artifact:*.cef.fileName","filtered-data:filter_file_artifacts:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'detonate_file_1' call
    for filtered_artifact_0_item_filter_file_artifacts in filtered_artifact_0_data_filter_file_artifacts:
        if filtered_artifact_0_item_filter_file_artifacts[0] is not None and filtered_artifact_0_item_filter_file_artifacts[1] is not None:
            parameters.append({
                "vault_id": filtered_artifact_0_item_filter_file_artifacts[0],
                "file_name": filtered_artifact_0_item_filter_file_artifacts[1],
                "context": {'artifact_id': filtered_artifact_0_item_filter_file_artifacts[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["rf sandbox"], callback=get_status_1)

    return


@phantom.playbook_block()
def get_files_from_vault(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_files_from_vault() called")

    id_value = container.get("id", None)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug('phantom.vault_info start')

    success, message, info = phantom.vault_info(
        container_id=id_value
    )

    for item in info:
        raw = {}
        cef = {}
        cef['vaultId'] = item['vault_id']
        cef['fileName'] = item['name']
        cef['fileHashSha256'] = item['metadata']['sha256']
        phantom.debug(cef)
        
        success, message, artifact_id = phantom.add_artifact(
        container=container, raw_data=raw, cef_data=cef, label='event',
        name='file', severity='high',
        identifier=None,
        artifact_type='file')
        phantom.debug('artifact added as id:'+str(artifact_id))

    ################################################################################
    ## Custom Code End
    ################################################################################

    filter_file_artifacts(container=container)

    return


@phantom.playbook_block()
def filter_file_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_file_artifacts() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "file"]
        ],
        name="filter_file_artifacts:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_status_1:action_result.data.*.status", "==", "reported"]
        ],
        scope="all")

    # call connected blocks if condition 1 matched
    if found_match_1:
        fetch_file_report(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    get_status_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def fetch_file_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("fetch_file_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_status_1_result_data = phantom.collect2(container=container, datapath=["get_status_1:action_result.data.*.analysis_id","get_status_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'fetch_file_report' call
    for get_status_1_result_item in get_status_1_result_data:
        if get_status_1_result_item[0] is not None:
            parameters.append({
                "analysis_id": get_status_1_result_item[0],
                "context": {'artifact_id': get_status_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("fetch report", parameters=parameters, name="fetch_file_report", assets=["rf sandbox"])

    return


@phantom.playbook_block()
def get_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_status_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_file_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_1:action_result.data.*.analysis_id","detonate_file_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_status_1' call
    for detonate_file_1_result_item in detonate_file_1_result_data:
        if detonate_file_1_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_file_1_result_item[0],
                "context": {'artifact_id': detonate_file_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # calculate start time using delay of 4 minutes
    start_time = datetime.now() + timedelta(minutes=4)
    phantom.act("get status", parameters=parameters, name="get_status_1", start_time=start_time, assets=["rf sandbox"], callback=decision_5)

    return


@phantom.playbook_block()
def filter_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_urls() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_urls:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_url_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_url_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_urls = phantom.collect2(container=container, datapath=["filtered-data:filter_urls:condition_1:artifact:*.cef.requestURL","filtered-data:filter_urls:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'detonate_url_1' call
    for filtered_artifact_0_item_filter_urls in filtered_artifact_0_data_filter_urls:
        if filtered_artifact_0_item_filter_urls[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_urls[0],
                "kind": "url",
                "context": {'artifact_id': filtered_artifact_0_item_filter_urls[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="detonate_url_1", assets=["rf sandbox"], callback=get_status_2)

    return


@phantom.playbook_block()
def get_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_status_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_url_1_result_data = phantom.collect2(container=container, datapath=["detonate_url_1:action_result.data.*.analysis_id","detonate_url_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_status_2' call
    for detonate_url_1_result_item in detonate_url_1_result_data:
        if detonate_url_1_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_url_1_result_item[0],
                "context": {'artifact_id': detonate_url_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # calculate start time using delay of 4 minutes
    start_time = datetime.now() + timedelta(minutes=4)
    phantom.act("get status", parameters=parameters, name="get_status_2", start_time=start_time, assets=["rf sandbox"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_status_2:action_result.data.*.status", "==", "reported"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        fetch_url_report(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def fetch_url_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("fetch_url_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_status_2_result_data = phantom.collect2(container=container, datapath=["get_status_2:action_result.data.*.analysis_id","get_status_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'fetch_url_report' call
    for get_status_2_result_item in get_status_2_result_data:
        if get_status_2_result_item[0] is not None:
            parameters.append({
                "analysis_id": get_status_2_result_item[0],
                "context": {'artifact_id': get_status_2_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("fetch report", parameters=parameters, name="fetch_url_report", assets=["rf sandbox"])

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The report was fetched before completion. Increase the delay timer and try again. ")

    return


@phantom.playbook_block()
def get_status_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_status_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_file_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_1:action_result.data.*.analysis_id","detonate_file_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_status_3' call
    for detonate_file_1_result_item in detonate_file_1_result_data:
        if detonate_file_1_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_file_1_result_item[0],
                "context": {'artifact_id': detonate_file_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get status", parameters=parameters, name="get_status_3", assets=["rf sandbox"], callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_status_3:action_result.data.*.status", "==", "reported"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        fetch_report_3(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_comment_2(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def fetch_report_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("fetch_report_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_status_3_result_data = phantom.collect2(container=container, datapath=["get_status_3:action_result.data.*.analysis_id","get_status_3:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'fetch_report_3' call
    for get_status_3_result_item in get_status_3_result_data:
        if get_status_3_result_item[0] is not None:
            parameters.append({
                "analysis_id": get_status_3_result_item[0],
                "context": {'artifact_id': get_status_3_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("fetch report", parameters=parameters, name="fetch_report_3", assets=["rf sandbox"])

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="The file report was fetched before completion. Increase the delay timer and try again. ")

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