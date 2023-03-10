"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'please_provide_inputs_to_search_the_emails' block
    please_provide_inputs_to_search_the_emails(container=container)

    return

@phantom.playbook_block()
def please_provide_inputs_to_search_the_emails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("please_provide_inputs_to_search_the_emails() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Please provide inputs to search the emails.\nNote: For optional parameters, please provide space for blank input."""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Subjects",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Senders",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Attachment names",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Attachment Hash Match Criteria",
            "options": {
                "type": "list",
                "choices": [
                    "ANY",
                    "ALL"
                ],
            },
        },
        {
            "prompt": "Attachment Hashes",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Attachment Mime Types",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Attachment Exclude Mime Types",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Domain Match Criteria",
            "options": {
                "type": "list",
                "choices": [
                    "ANY",
                    "ALL"
                ],
            },
        },
        {
            "prompt": "Domains",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Headers",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Internet Message ID",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Partial Ingest",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Received After Date",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Received Before Date",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Recipient",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "URL",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Message size",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="please_provide_inputs_to_search_the_emails", parameters=parameters, response_types=response_types, callback=decision_6)

    return


@phantom.playbook_block()
def create_message_search_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_message_search_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    please_provide_inputs_to_search_the_emails_result_data = phantom.collect2(container=container, datapath=["please_provide_inputs_to_search_the_emails:action_result.summary.responses.15","please_provide_inputs_to_search_the_emails:action_result.summary.responses.8","please_provide_inputs_to_search_the_emails:action_result.summary.responses.9","please_provide_inputs_to_search_the_emails:action_result.summary.responses.1","please_provide_inputs_to_search_the_emails:action_result.summary.responses.0","please_provide_inputs_to_search_the_emails:action_result.summary.responses.14","please_provide_inputs_to_search_the_emails:action_result.summary.responses.2","please_provide_inputs_to_search_the_emails:action_result.summary.responses.4","please_provide_inputs_to_search_the_emails:action_result.summary.responses.10","please_provide_inputs_to_search_the_emails:action_result.summary.responses.12","please_provide_inputs_to_search_the_emails:action_result.summary.responses.13","please_provide_inputs_to_search_the_emails:action_result.summary.responses.5","please_provide_inputs_to_search_the_emails:action_result.summary.responses.7","please_provide_inputs_to_search_the_emails:action_result.summary.responses.6","please_provide_inputs_to_search_the_emails:action_result.summary.responses.3","please_provide_inputs_to_search_the_emails:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_message_search_1' call
    for please_provide_inputs_to_search_the_emails_result_item in please_provide_inputs_to_search_the_emails_result_data:
        if please_provide_inputs_to_search_the_emails_result_item[12] is not None and please_provide_inputs_to_search_the_emails_result_item[14] is not None:
            parameters.append({
                "url": please_provide_inputs_to_search_the_emails_result_item[0],
                "domains": please_provide_inputs_to_search_the_emails_result_item[1],
                "headers": please_provide_inputs_to_search_the_emails_result_item[2],
                "senders": please_provide_inputs_to_search_the_emails_result_item[3],
                "subjects": please_provide_inputs_to_search_the_emails_result_item[4],
                "recipient": please_provide_inputs_to_search_the_emails_result_item[5],
                "attachment_names": please_provide_inputs_to_search_the_emails_result_item[6],
                "attachment_hashes": please_provide_inputs_to_search_the_emails_result_item[7],
                "internet_message_id": please_provide_inputs_to_search_the_emails_result_item[8],
                "received_after_date": please_provide_inputs_to_search_the_emails_result_item[9],
                "received_before_date": please_provide_inputs_to_search_the_emails_result_item[10],
                "attachment_mime_types": please_provide_inputs_to_search_the_emails_result_item[11],
                "domain_match_criteria": please_provide_inputs_to_search_the_emails_result_item[12],
                "attachment_exclude_mime_types": please_provide_inputs_to_search_the_emails_result_item[13],
                "attachment_hash_match_criteria": please_provide_inputs_to_search_the_emails_result_item[14],
                "context": {'artifact_id': please_provide_inputs_to_search_the_emails_result_item[15]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    custom_result_data = phantom.collect2(container=container, datapath=["please_provide_inputs_to_search_the_emails:action_result.summary.responses.11"], action_results=results)
    parameters[0].update({"partial_ingest": True if custom_result_data[0][0] == "Yes" else False})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create message search", parameters=parameters, name="create_message_search_1", assets=["cofensevision"], callback=decision_1)

    return


@phantom.playbook_block()
def get_message_metadata_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_message_metadata_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_messagesearch_results_1_result_data = phantom.collect2(container=container, datapath=["get_messagesearch_results_1:action_result.data.*.recipients","get_messagesearch_results_1:action_result.data.*.internetMessageId","get_messagesearch_results_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # build parameters list for 'get_message_metadata_1' call
    for get_messagesearch_results_1_result_item in get_messagesearch_results_1_result_data:
        i = get_messagesearch_results_1_result_item[0][0]
        parameters.append({
            "recipient_address": i["address"],
            "internet_message_id": get_messagesearch_results_1_result_item[1],
            "context": {'artifact_id': get_messagesearch_results_1_result_item[2]},
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get message metadata", parameters=parameters, name="get_message_metadata_1", assets=["cofensevision"], callback=decision_4)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["create_message_search_1:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_messagesearch_results_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def get_messagesearch_results_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_messagesearch_results_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_message_search_1_result_data = phantom.collect2(container=container, datapath=["create_message_search_1:action_result.data.*.id","create_message_search_1:action_result.parameter.context.artifact_id"], action_results=results)
    please_provide_inputs_to_search_the_emails_result_data = phantom.collect2(container=container, datapath=["please_provide_inputs_to_search_the_emails:action_result.summary.responses.16","please_provide_inputs_to_search_the_emails:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_messagesearch_results_1' call
    for create_message_search_1_result_item in create_message_search_1_result_data:
        for please_provide_inputs_to_search_the_emails_result_item in please_provide_inputs_to_search_the_emails_result_data:
            if create_message_search_1_result_item[0] is not None and please_provide_inputs_to_search_the_emails_result_item[0] is not None:
                parameters.append({
                    "id": create_message_search_1_result_item[0],
                    "page": 0,
                    "size": please_provide_inputs_to_search_the_emails_result_item[0],
                    "context": {'artifact_id': please_provide_inputs_to_search_the_emails_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get messagesearch results", parameters=parameters, name="get_messagesearch_results_1", assets=["cofensevision"], callback=decision_2)

    return


@phantom.playbook_block()
def do_you_want_to_get_message_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("do_you_want_to_get_message_content() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Do you want to get message content?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Retrieve message content.",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="do_you_want_to_get_message_content", parameters=parameters, response_types=response_types, callback=decision_3)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_messagesearch_results_1:action_result.summary.total_results", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        do_you_want_to_get_message_content(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["do_you_want_to_get_message_content:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_message_metadata_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_do_you_want_to_quarantine_messages(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_message_metadata_1:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_do_you_want_to_quarantine_messages(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_do_you_want_to_quarantine_messages(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_do_you_want_to_quarantine_messages() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_do_you_want_to_quarantine_messages_called"):
        return

    if phantom.completed(action_names=["do_you_want_to_get_message_content"]):
        # save the state that the joined function has now been called
        phantom.save_run_data(key="join_do_you_want_to_quarantine_messages_called", value="do_you_want_to_quarantine_messages")

        # call connected block "do_you_want_to_quarantine_messages"
        do_you_want_to_quarantine_messages(container=container, handle=handle)

    return


@phantom.playbook_block()
def do_you_want_to_quarantine_messages(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("do_you_want_to_quarantine_messages() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Do you want to quarantine messages?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Quarantine",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="do_you_want_to_quarantine_messages", parameters=parameters, response_types=response_types, callback=decision_5)

    return


@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["do_you_want_to_quarantine_messages:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        create_quarantine_job_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def create_quarantine_job_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_quarantine_job_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    result_data = phantom.collect2(container=container, datapath=["get_messagesearch_results_1:action_result.data.*.internetMessageId","get_messagesearch_results_1:action_result.data.*.recipients"], action_results=results)
    
    quarantine_emails = ', '.join(', '.join(f'{recipient["address"]}:{data[0]}' for recipient in data[1]) for data in result_data)
    
    parameters.append({
        "quarantine_emails": quarantine_emails,
    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create quarantine job", parameters=parameters, name="create_quarantine_job_1", assets=["cofensevision"])

    return

@phantom.playbook_block()
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_6() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["please_provide_inputs_to_search_the_emails:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        create_message_search_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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