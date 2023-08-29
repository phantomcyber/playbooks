"""
Detonates file on ReversingLabs TitaniumScale instance and retrieves report.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'titaniumscale_detonate_file' block
    titaniumscale_detonate_file(container=container)

    return

@phantom.playbook_block()
def titaniumscale_detonate_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("titaniumscale_detonate_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.vaultId","artifact:*.id"])

    parameters = []

    # build parameters list for 'titaniumscale_detonate_file' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "vault_id": container_artifact_item[0],
                "full_report": True,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file and get report", parameters=parameters, name="titaniumscale_detonate_file", assets=["reversinglabs_titaniumscale_v2"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    detonate_file_and_get_report_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_and_get_report_1:action_result.data.*.tc_report.classification.classification"])

    detonate_file_and_get_report_1_result_item_0 = [item[0] for item in detonate_file_and_get_report_1_result_data]

    output = {
        "classification": detonate_file_and_get_report_1_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return