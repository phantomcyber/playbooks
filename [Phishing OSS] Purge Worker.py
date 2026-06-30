"""
This playbook trashes phishing emails from a user&#39;s inbox after a confirmed threat has been analyzed.\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'search_email' block
    search_email(container=container)

    return

@phantom.playbook_block()
def search_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("search_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_splunker_email = phantom.collect2(container=container, datapath=["playbook_input:splunker_email"])
    playbook_input_email_sender = phantom.collect2(container=container, datapath=["playbook_input:email_sender"])
    playbook_input_email_subject = phantom.collect2(container=container, datapath=["playbook_input:email_subject"])

    parameters = []

    # build parameters list for 'search_email' call
    for playbook_input_splunker_email_item in playbook_input_splunker_email:
        for playbook_input_email_sender_item in playbook_input_email_sender:
            for playbook_input_email_subject_item in playbook_input_email_subject:
                if playbook_input_splunker_email_item[0] is not None:
                    parameters.append({
                        "email": playbook_input_splunker_email_item[0],
                        "label": "",
                        "sender": playbook_input_email_sender_item[0],
                        "subject": playbook_input_email_subject_item[0],
                        "max_results": 100,
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_email", assets=["gmail"], callback=decision_1)

    return


@phantom.playbook_block()
def purge_email_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("purge_email_id() called")

    search_email_result_data = phantom.collect2(container=container, datapath=["search_email:action_result.data.*.id"], action_results=results)

    search_email_result_item_0 = [item[0] for item in search_email_result_data]

    purge_email_id__purge_email_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    purge_email_id__purge_email_id=search_email_result_item_0[0]
    phantom.debug(purge_email_id__purge_email_id)
   
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="purge_email_id__inputs:0:search_email:action_result.data.*.id", value=json.dumps(search_email_result_item_0))

    phantom.save_block_result(key="purge_email_id:purge_email_id", value=json.dumps(purge_email_id__purge_email_id))

    phantom.save_block_result(key="purge_email_id_called", value="True")

    trash_email_3(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["search_email:action_result.summary.total_messages_returned", "!=", 0]
        ],
        conditions_dps=[
            ["search_email:action_result.summary.total_messages_returned", "!=", 0]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        purge_email_id(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def trash_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("trash_email_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_splunker_email = phantom.collect2(container=container, datapath=["playbook_input:splunker_email"])
    purge_email_id__purge_email_id = json.loads(_ if (_ := phantom.get_run_data(key="purge_email_id:purge_email_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'trash_email_3' call
    for playbook_input_splunker_email_item in playbook_input_splunker_email:
        if purge_email_id__purge_email_id is not None and playbook_input_splunker_email_item[0] is not None:
            parameters.append({
                "id": purge_email_id__purge_email_id,
                "email": playbook_input_splunker_email_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("trash email", parameters=parameters, name="trash_email_3", assets=["gmail"])

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