"""
Queries ReversingLabs A1000 appliance for classification report.  If file is not present on te appliance, uploads the file and retrieves report.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_detailed_report_1' block
    get_detailed_report_1(container=container)

    return

@phantom.playbook_block()
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_detailed_report_1_result_data = phantom.collect2(container=container, datapath=["get_detailed_report_1:action_result.parameter.hash","get_detailed_report_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'detonate_file_1' call
    for get_detailed_report_1_result_item in get_detailed_report_1_result_data:
        if get_detailed_report_1_result_item[0] is not None:
            parameters.append({
                "vault_id": get_detailed_report_1_result_item[0],
                "file_name": "sample",
                "context": {'artifact_id': get_detailed_report_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["reversinglabs_a1000_v2"], callback=get_detailed_report_2)

    return


@phantom.playbook_block()
def get_detailed_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_detailed_report_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'get_detailed_report_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "retry": True,
                "hash": container_artifact_item[0],
                "skip_reanalysis": True,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get detailed report", parameters=parameters, name="get_detailed_report_1", assets=["reversinglabs_a1000_v2"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_detailed_report_1:action_result.status", "==", "failed"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def get_detailed_report_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_detailed_report_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_file_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_1:action_result.parameter.vault_id","detonate_file_1:action_result.parameter.context.artifact_id"], action_results=results, scope="all")

    parameters = []

    # build parameters list for 'get_detailed_report_2' call
    for detonate_file_1_result_item in detonate_file_1_result_data:
        if detonate_file_1_result_item[0] is not None:
            parameters.append({
                "retry": True,
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

    phantom.act("get detailed report", parameters=parameters, name="get_detailed_report_2", assets=["reversinglabs_a1000_v2"])

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