"""
Queries ReversingLabs TitaniumCloud for url reputation.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'titaniumcloud_url_reputation' block
    titaniumcloud_url_reputation(container=container)

    return

@phantom.playbook_block()
def titaniumcloud_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("titaniumcloud_url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'titaniumcloud_url_reputation' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="titaniumcloud_url_reputation", assets=["url-dev-test"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    titaniumcloud_url_reputation_result_data = phantom.collect2(container=container, datapath=["titaniumcloud_url_reputation:action_result.data*.rl.classification."])

    titaniumcloud_url_reputation_result_item_0 = [item[0] for item in titaniumcloud_url_reputation_result_data]

    output = {
        "classification": titaniumcloud_url_reputation_result_item_0,
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