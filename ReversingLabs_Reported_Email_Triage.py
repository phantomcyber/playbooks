"""

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
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""$filter=contains(subject, '{0}')""",
        parameters=[
            "filtered-data:filter_2:condition_1:artifact:*.cef.evidence.1.networkMessageId"
        ])

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.evidence.1.networkMessageId","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'run_query_1' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        parameters.append({
            "folder": "Inbox",
            "get_folder_id": True,
            "email_address": "secops@company.com",
            "subject": "",
            "query": query_formatted_string,
            "limit": 1,
            "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["o365_rldevelopment"], callback=get_email_1)

    return


@phantom.playbook_block()
def get_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data.*.id","run_query_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_email_1' call
    for run_query_1_result_item in run_query_1_result_data:
        if run_query_1_result_item[0] is not None:
            parameters.append({
                "id": run_query_1_result_item[0],
                "email_address": "secops@company.com",
                "download_attachments": True,
                "download_email": False,
                "context": {'artifact_id': run_query_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get email", parameters=parameters, name="get_email_1", assets=["o365_rldevelopment"], callback=detonate_file_1)

    return


@phantom.playbook_block()
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_email_1_result_data = phantom.collect2(container=container, datapath=["get_email_1:action_result.data.*.attachments.*.vaultId","get_email_1:action_result.data.*.attachments.*.name","get_email_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'detonate_file_1' call
    for get_email_1_result_item in get_email_1_result_data:
        if get_email_1_result_item[0] is not None:
            parameters.append({
                "vault_id": get_email_1_result_item[0],
                "file_name": get_email_1_result_item[1],
                "context": {'artifact_id': get_email_1_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["a1000-techalc1"], callback=get_summary_report_1)

    return


@phantom.playbook_block()
def get_summary_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_summary_report_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_file_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_1:action_result.parameter.vault_id","detonate_file_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_summary_report_1' call
    for detonate_file_1_result_item in detonate_file_1_result_data:
        if detonate_file_1_result_item[0] is not None:
            parameters.append({
                "retry": True,
                "include_network_threat_intelligence": True,
                "hash": detonate_file_1_result_item[0],
                "skip_reanalysis": True,
                "context": {'artifact_id': detonate_file_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get summary report", parameters=parameters, name="get_summary_report_1", assets=["a1000-techalc1"])

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email reported by user as malware or phish"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_query_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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