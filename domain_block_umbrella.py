"""
Block a domain using Cisco Umbrella.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'cisco_umbrella_block_domain' block
    cisco_umbrella_block_domain(container=container)

    return

def cisco_umbrella_block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("cisco_umbrella_block_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_domain = phantom.collect2(container=container, datapath=["playbook_input:domain"])

    parameters = []

    # build parameters list for 'cisco_umbrella_block_domain' call
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

    phantom.act("block domain", parameters=parameters, name="cisco_umbrella_block_domain", assets=["cisco_umbrella"], callback=check_success)

    return


def tag_blocked_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_blocked_domain() called")

    filtered_result_0_data_check_success = phantom.collect2(container=container, datapath=["filtered-data:check_success:condition_1:cisco_umbrella_block_domain:action_result.parameter.domain"])

    parameters = []

    # build parameters list for 'tag_blocked_domain' call
    for filtered_result_0_item_check_success in filtered_result_0_data_check_success:
        parameters.append({
            "indicator": filtered_result_0_item_check_success[0],
            "tags": "blocked",
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_blocked_domain")

    return


def check_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_success() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["cisco_umbrella_block_domain:action_result.status", "==", "success"]
        ],
        name="check_success:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        tag_blocked_domain(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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