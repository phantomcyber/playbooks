"""
This playbook detects duplicate email threads to avoid re-processing emails that are part of an existing conversation (e.g., replies in an ongoing thread).
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        name="filter_1:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ispreviousemailthread(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ispreviousemailthread(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ispreviousemailthread() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.References"])

    filtered_artifact_0__cef_emailheaders_references = [item[0] for item in filtered_artifact_0_data_filter_1]

    ispreviousemailthread__isthreadflag = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ispreviousemailthread__isthreadflag = False
    referenceFound = False
    
    phantom.debug(filtered_artifact_0__cef_emailheaders_references)
    
    if(filtered_artifact_0__cef_emailheaders_references[0]):
        success, message, execs = phantom.get_list(list_name='Ingested_Email_Message_ID')
    
        phantom.error(
        'phantom.get_list results: success: {}, message: {}, execs: {}'\
        .format(success, message, execs)
        )
        
        for i in execs:
            for item in i:
                phantom.debug(str(i[0])+" : i[0]")
                phantom.debug(str(filtered_artifact_0__cef_emailheaders_references[0])+" : filtered_artifact_0__cef_emailheaders_references")
                if str(i[0]) in str(filtered_artifact_0__cef_emailheaders_references[0]):  # If previously seen message_id is present in the References header of this message. This message is part of a previous conversation.
                    referenceFound=True
    
    if (filtered_artifact_0__cef_emailheaders_references and referenceFound):
        ispreviousemailthread__isthreadflag=True

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="ispreviousemailthread__inputs:0:filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.References", value=json.dumps(filtered_artifact_0__cef_emailheaders_references))

    phantom.save_block_result(key="ispreviousemailthread:isthreadflag", value=json.dumps(ispreviousemailthread__isthreadflag))

    phantom.save_block_result(key="ispreviousemailthread_called", value="True")

    filter_2(container=container)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["ispreviousemailthread:custom_function:isthreadflag", "!=", True]
        ],
        conditions_dps=[
            ["ispreviousemailthread:custom_function:isthreadflag", "!=", True]
        ],
        name="filter_2:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_to_ingested_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["ispreviousemailthread:custom_function:isthreadflag", "==", True]
        ],
        conditions_dps=[
            ["ispreviousemailthread:custom_function:isthreadflag", "==", True]
        ],
        name="filter_2:condition_2",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        set_container_custom_data_dey_value_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def add_to_ingested_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_to_ingested_list() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef.emailHeaders.Message-ID"])

    filtered_artifact_0__cef_emailheaders_message_id = [item[0] for item in filtered_artifact_0_data_filter_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_list(list_name="Ingested_Email_Message_ID", values=filtered_artifact_0__cef_emailheaders_message_id)

    set_container_custom_data_dey_value_6(container=container)

    return


@phantom.playbook_block()
def add_tag_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_tag_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_tags(container=container, tags="PreviousThread")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def set_container_custom_data_dey_value_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_container_custom_data_dey_value_5() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "PreviousThreadFlag",
        "custom_value": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/set_container_custom_data_dey_value", parameters=parameters, name="set_container_custom_data_dey_value_5", callback=add_tag_4)

    return


@phantom.playbook_block()
def set_container_custom_data_dey_value_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_container_custom_data_dey_value_6() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "PreviousThreadFlag",
        "custom_value": False,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/set_container_custom_data_dey_value", parameters=parameters, name="set_container_custom_data_dey_value_6")

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