"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_alert_name' block
    filter_alert_name(container=container)

    return

@phantom.playbook_block()
def run_email_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_email_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""$filter=contains(subject, '{0}')""",
        parameters=[
            "filtered-data:filter_alert_name:condition_1:artifact:*.cef.evidence.1.networkMessageId"
        ])

    filtered_artifact_0_data_filter_alert_name = phantom.collect2(container=container, datapath=["filtered-data:filter_alert_name:condition_1:artifact:*.cef.evidence.1.networkMessageId","filtered-data:filter_alert_name:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'run_email_query' call
    for filtered_artifact_0_item_filter_alert_name in filtered_artifact_0_data_filter_alert_name:
        parameters.append({
            "limit": 1,
            "query": query_formatted_string,
            "folder": "Inbox",
            "subject": "",
            "email_address": "",
            "get_folder_id": True,
            "context": {'artifact_id': filtered_artifact_0_item_filter_alert_name[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_email_query", assets=["ms_graph_for_office_365"], callback=get_reported_emails)

    return


@phantom.playbook_block()
def get_reported_emails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_reported_emails() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    run_email_query_result_data = phantom.collect2(container=container, datapath=["run_email_query:action_result.data.*.id","run_email_query:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_reported_emails' call
    for run_email_query_result_item in run_email_query_result_data:
        if run_email_query_result_item[0] is not None:
            parameters.append({
                "id": run_email_query_result_item[0],
                "email_address": "",
                "download_email": False,
                "download_attachments": True,
                "context": {'artifact_id': run_email_query_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get email", parameters=parameters, name="get_reported_emails", assets=["ms_graph_for_office_365"], callback=analyze_attachment)

    return


@phantom.playbook_block()
def analyze_attachment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("analyze_attachment() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_reported_emails_result_data = phantom.collect2(container=container, datapath=["get_reported_emails:action_result.data.*.attachments.*.vaultId","get_reported_emails:action_result.data.*.attachments.*.name","get_reported_emails:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'analyze_attachment' call
    for get_reported_emails_result_item in get_reported_emails_result_data:
        if get_reported_emails_result_item[0] is not None:
            parameters.append({
                "vault_id": get_reported_emails_result_item[0],
                "file_name": get_reported_emails_result_item[1],
                "context": {'artifact_id': get_reported_emails_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="analyze_attachment", assets=["reversinglabs_a1000_v2"], callback=get_analysis_report)

    return


@phantom.playbook_block()
def get_analysis_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_analysis_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    analyze_attachment_result_data = phantom.collect2(container=container, datapath=["analyze_attachment:action_result.parameter.vault_id","analyze_attachment:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_analysis_report' call
    for analyze_attachment_result_item in analyze_attachment_result_data:
        if analyze_attachment_result_item[0] is not None:
            parameters.append({
                "hash": analyze_attachment_result_item[0],
                "retry": True,
                "skip_reanalysis": True,
                "include_network_threat_intelligence": True,
                "context": {'artifact_id': analyze_attachment_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get summary report", parameters=parameters, name="get_analysis_report", assets=["reversinglabs_a1000_v2"])

    return


@phantom.playbook_block()
def filter_alert_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_alert_name() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email reported by user as malware or phish"]
        ],
        name="filter_alert_name:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_email_query(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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