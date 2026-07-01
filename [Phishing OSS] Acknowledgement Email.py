"""
This is a playbook for automated phishing report acknowledgment. It processes emails submitted to phishing inbox and sends appropriate automated responses based on how the user submitted their report.\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Attached Suspicious Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Attached Suspicious Email", "in", "artifact:*.name"]
        ],
        name="filter_1:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:phishing_inbox_email", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"]
        ],
        conditions_dps=[
            ["playbook_input:phishing_inbox_email", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"]
        ],
        name="filter_2:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:phishing_inbox_email", "not in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"]
        ],
        conditions_dps=[
            ["playbook_input:phishing_inbox_email", "not in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"]
        ],
        name="filter_2:condition_2",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_3() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        name="filter_3:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        correct_email_attached_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_4() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        name="filter_4:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        wrong_email_attached_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def wrong_email_attached_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("wrong_email_attached_format() called")

    template = """<p>Hello {0},</p>\n<p>Whoops! It looks like you accidentally forwarded the wrong email to the phishing inbox. Please re-send it as an attachment using the following process:</p>\n\n<p style=\"padding-left: 30px;\"><strong>Using Gmail:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>In the original email, click the three dots in the top right corner - click \"download message\" - and then forward that download as an attachment to {1}</li>\n</ul>\n\n<p style=\"padding-left: 30px;\"><strong>If using Outlook on a Mac:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>If the message is open, you can select <u>Forward as Attachment</u>.</li>\n  <li>If you don't have the message open, you can <u>right click</u> the message from the Outlook listing and select Forward as Attachment from the popup menu.</li>\n</ul>\n\n<p style=\"padding-left: 30px;\"><strong>If using OWA or Outlook on Windows:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>Click \"New mail,\" then drag and drop the email you wish to forward into the body of the new message. It will appear as an attachment -- send this new message to {1}.</li>\n</ul>\n\n<p>Your help in improving the overall security posture at Splunk is greatly appreciated!</p>\n<p>Thank you,<br />\nThreat Response - Security Operations Center<br />\n<a href=\"mailto:{1}\">{1}</a></p>"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:artifact:*.cef.fromEmail",
        "playbook_input:phishing_inbox_email"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="wrong_email_attached_format")

    add_reference_to_wrong_email_response(container=container)

    return


@phantom.playbook_block()
def correct_email_attached_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("correct_email_attached_format() called")

    template = """<p>Hello {0},</p>\n<p>Thank you for reporting suspicious emails to Phishing inbox. We have received your email and will perform analysis of the content. In the meantime, please do not click on any links or attachments in this email to be safe.</p>\n<p>Your help in improving the overall security posture at Splunk is greatly appreciated!</p>\n<p>Thank you,<br />\nThreat Response - Security Operations Center<br />\n<a href=\"mailto:{1}\">{1}</a></p>\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:artifact:*.cef.fromEmail",
        "playbook_input:phishing_inbox_email"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="correct_email_attached_format")

    add_references_to_correct_email_response(container=container)

    return


@phantom.playbook_block()
def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_5() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Reporter Email", "in", "artifact:*.name"]
        ],
        name="filter_5:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        no_email_attached(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def no_email_attached(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("no_email_attached() called")

    template = """<p>Hello {0},</p>\n<p>Whoops! It looks like you accidentally forwarded the wrong email to the phishing pond. Please re-send it as an attachment using the following process:</p>\n\n<p style=\"padding-left: 30px;\"><strong>Using Gmail:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>In the original email, click the three dots in the top right corner - click \"download message\" - and then forward that download as an attachment to {1}</li>\n</ul>\n\n<p style=\"padding-left: 30px;\"><strong>If using Outlook on a Mac:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>If the message is open, you can select <u>Forward as Attachment</u>.</li>\n  <li>If you don't have the message open, you can <u>right click</u> the message from the Outlook listing and select Forward as Attachment from the popup menu.</li>\n</ul>\n\n<p style=\"padding-left: 30px;\"><strong>If using OWA or Outlook on Windows:</strong></p>\n<ul style=\"padding-left: 30px;\">\n  <li>Click \"New mail,\" then drag and drop the email you wish to forward into the body of the new message. It will appear as an attachment -- send this new message to {1}.</li>\n</ul>\n\n<p>Your help in improving the overall security posture at Splunk is greatly appreciated!</p>\n<p>Thank you,<br />\nThreat Response - Security Operations Center<br />\n<a href=\"mailto:{1}\">{1}</a></p>"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_5:condition_1:artifact:*.cef.fromEmail",
        "playbook_input:phishing_inbox_email"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="no_email_attached")

    add_reference_to_forward_response(container=container)

    return


@phantom.playbook_block()
def add_reference_to_forward_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_reference_to_forward_response() called")

    filtered_artifact_0_data_filter_5 = phantom.collect2(container=container, datapath=["filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.Message-ID","filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.References"])

    filtered_artifact_0__cef_emailheaders_message_id = [item[0] for item in filtered_artifact_0_data_filter_5]
    filtered_artifact_0__cef_emailheaders_references = [item[1] for item in filtered_artifact_0_data_filter_5]

    add_reference_to_forward_response__references_value = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    add_reference_to_forward_response__references_value=""
    if(filtered_artifact_0__cef_emailheaders_message_id and filtered_artifact_0__cef_emailheaders_message_id!=[] ):
        phantom.debug(filtered_artifact_0__cef_emailheaders_message_id)
        if(filtered_artifact_0__cef_emailheaders_message_id[0]):
            add_reference_to_forward_response__references_value="".join(filtered_artifact_0__cef_emailheaders_message_id[0].split())
    
    if(filtered_artifact_0__cef_emailheaders_references and filtered_artifact_0__cef_emailheaders_references!=[]):
        phantom.debug(filtered_artifact_0__cef_emailheaders_references)
        if(filtered_artifact_0__cef_emailheaders_references[0]):
            add_reference_to_forward_response__references_value+="".join(filtered_artifact_0__cef_emailheaders_references[0].split())

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_reference_to_forward_response__inputs:0:filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.Message-ID", value=json.dumps(filtered_artifact_0__cef_emailheaders_message_id))
    phantom.save_block_result(key="add_reference_to_forward_response__inputs:1:filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.References", value=json.dumps(filtered_artifact_0__cef_emailheaders_references))

    phantom.save_block_result(key="add_reference_to_forward_response:references_value", value=json.dumps(add_reference_to_forward_response__references_value))

    phantom.save_block_result(key="add_reference_to_forward_response_called", value="True")

    send_htmlemail_1(container=container)

    return


@phantom.playbook_block()
def send_htmlemail_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_htmlemail_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    headers_formatted_string = phantom.format(
        container=container,
        template="""{{\"References\":\"{0}\"\n}}""",
        parameters=[
            "add_reference_to_forward_response:custom_function:references_value"
        ])
    subject_formatted_string = phantom.format(
        container=container,
        template="""Re: {0}""",
        parameters=[
            "filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.Subject"
        ])

    filtered_artifact_0_data_filter_5 = phantom.collect2(container=container, datapath=["filtered-data:filter_5:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_5:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_5:condition_1:artifact:*.id"])
    playbook_input_phishing_inbox_email = phantom.collect2(container=container, datapath=["playbook_input:phishing_inbox_email"])
    no_email_attached = phantom.get_format_data(name="no_email_attached")
    add_reference_to_forward_response__references_value = json.loads(_ if (_ := phantom.get_run_data(key="add_reference_to_forward_response:references_value")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'send_htmlemail_1' call
    for filtered_artifact_0_item_filter_5 in filtered_artifact_0_data_filter_5:
        for playbook_input_phishing_inbox_email_item in playbook_input_phishing_inbox_email:
            if filtered_artifact_0_item_filter_5[0] is not None and no_email_attached is not None:
                parameters.append({
                    "cc": "",
                    "to": filtered_artifact_0_item_filter_5[0],
                    "from": playbook_input_phishing_inbox_email_item[0],
                    "headers": headers_formatted_string,
                    "subject": subject_formatted_string,
                    "html_body": no_email_attached,
                    "context": {'artifact_id': filtered_artifact_0_item_filter_5[2]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send htmlemail", parameters=parameters, name="send_htmlemail_1", assets=["smtp"])

    return


@phantom.playbook_block()
def add_reference_to_wrong_email_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_reference_to_wrong_email_response() called")

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.Message-ID","filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.References"])

    filtered_artifact_0__cef_emailheaders_message_id = [item[0] for item in filtered_artifact_0_data_filter_4]
    filtered_artifact_0__cef_emailheaders_references = [item[1] for item in filtered_artifact_0_data_filter_4]

    add_reference_to_wrong_email_response__references_value = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    add_reference_to_wrong_email_response__references_value=""
    if(filtered_artifact_0__cef_emailheaders_message_id and filtered_artifact_0__cef_emailheaders_message_id!=[] ):
        phantom.debug(filtered_artifact_0__cef_emailheaders_message_id)
        if(filtered_artifact_0__cef_emailheaders_message_id[0]):
            add_reference_to_wrong_email_response__references_value="".join(filtered_artifact_0__cef_emailheaders_message_id[0].split())
    
    if(filtered_artifact_0__cef_emailheaders_references and filtered_artifact_0__cef_emailheaders_references!=[]):
        phantom.debug(filtered_artifact_0__cef_emailheaders_references)
        if(filtered_artifact_0__cef_emailheaders_references[0]):
            add_reference_to_wrong_email_response__references_value+="".join(filtered_artifact_0__cef_emailheaders_references[0].split())

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_reference_to_wrong_email_response__inputs:0:filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.Message-ID", value=json.dumps(filtered_artifact_0__cef_emailheaders_message_id))
    phantom.save_block_result(key="add_reference_to_wrong_email_response__inputs:1:filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.References", value=json.dumps(filtered_artifact_0__cef_emailheaders_references))

    phantom.save_block_result(key="add_reference_to_wrong_email_response:references_value", value=json.dumps(add_reference_to_wrong_email_response__references_value))

    phantom.save_block_result(key="add_reference_to_wrong_email_response_called", value="True")

    send_htmlemail_3(container=container)

    return


@phantom.playbook_block()
def add_references_to_correct_email_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_references_to_correct_email_response() called")

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.Message-ID","filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.References"])

    filtered_artifact_0__cef_emailheaders_message_id = [item[0] for item in filtered_artifact_0_data_filter_3]
    filtered_artifact_0__cef_emailheaders_references = [item[1] for item in filtered_artifact_0_data_filter_3]

    add_references_to_correct_email_response__references_value = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    add_references_to_correct_email_response__references_value=""
    if(filtered_artifact_0__cef_emailheaders_message_id and filtered_artifact_0__cef_emailheaders_message_id!=[] ):
        phantom.debug(filtered_artifact_0__cef_emailheaders_message_id)
        if(filtered_artifact_0__cef_emailheaders_message_id[0]):
            add_references_to_correct_email_response__references_value="".join(filtered_artifact_0__cef_emailheaders_message_id[0].split())
    
    if(filtered_artifact_0__cef_emailheaders_references and filtered_artifact_0__cef_emailheaders_references!=[]):
        phantom.debug(filtered_artifact_0__cef_emailheaders_references)
        if(filtered_artifact_0__cef_emailheaders_references[0]):
            add_references_to_correct_email_response__references_value+="".join(filtered_artifact_0__cef_emailheaders_references[0].split())

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="add_references_to_correct_email_response__inputs:0:filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.Message-ID", value=json.dumps(filtered_artifact_0__cef_emailheaders_message_id))
    phantom.save_block_result(key="add_references_to_correct_email_response__inputs:1:filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.References", value=json.dumps(filtered_artifact_0__cef_emailheaders_references))

    phantom.save_block_result(key="add_references_to_correct_email_response:references_value", value=json.dumps(add_references_to_correct_email_response__references_value))

    phantom.save_block_result(key="add_references_to_correct_email_response_called", value="True")

    send_htmlemail_2(container=container)

    return


@phantom.playbook_block()
def send_htmlemail_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_htmlemail_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    headers_formatted_string = phantom.format(
        container=container,
        template="""{{\"References\":\"{0}\"\n}}""",
        parameters=[
            "add_references_to_correct_email_response:custom_function:references_value"
        ])
    subject_formatted_string = phantom.format(
        container=container,
        template="""Re: {0}""",
        parameters=[
            "filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.Subject"
        ])

    filtered_artifact_0_data_filter_3 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_3:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_3:condition_1:artifact:*.id"])
    playbook_input_phishing_inbox_email = phantom.collect2(container=container, datapath=["playbook_input:phishing_inbox_email"])
    correct_email_attached_format = phantom.get_format_data(name="correct_email_attached_format")
    add_references_to_correct_email_response__references_value = json.loads(_ if (_ := phantom.get_run_data(key="add_references_to_correct_email_response:references_value")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'send_htmlemail_2' call
    for filtered_artifact_0_item_filter_3 in filtered_artifact_0_data_filter_3:
        for playbook_input_phishing_inbox_email_item in playbook_input_phishing_inbox_email:
            if filtered_artifact_0_item_filter_3[0] is not None and correct_email_attached_format is not None:
                parameters.append({
                    "cc": "",
                    "to": filtered_artifact_0_item_filter_3[0],
                    "from": playbook_input_phishing_inbox_email_item[0],
                    "headers": headers_formatted_string,
                    "subject": subject_formatted_string,
                    "html_body": correct_email_attached_format,
                    "context": {'artifact_id': filtered_artifact_0_item_filter_3[2]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send htmlemail", parameters=parameters, name="send_htmlemail_2", assets=["smtp"])

    return


@phantom.playbook_block()
def send_htmlemail_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_htmlemail_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    headers_formatted_string = phantom.format(
        container=container,
        template="""{{\"References\":\"{0}\"\n}}""",
        parameters=[
            "add_reference_to_wrong_email_response:custom_function:references_value"
        ])
    subject_formatted_string = phantom.format(
        container=container,
        template="""Re: {0}""",
        parameters=[
            "filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.Subject"
        ])

    filtered_artifact_0_data_filter_4 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_4:condition_1:artifact:*.cef.emailHeaders.Subject","filtered-data:filter_4:condition_1:artifact:*.id"])
    playbook_input_phishing_inbox_email = phantom.collect2(container=container, datapath=["playbook_input:phishing_inbox_email"])
    wrong_email_attached_format = phantom.get_format_data(name="wrong_email_attached_format")
    add_reference_to_wrong_email_response__references_value = json.loads(_ if (_ := phantom.get_run_data(key="add_reference_to_wrong_email_response:references_value")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'send_htmlemail_3' call
    for filtered_artifact_0_item_filter_4 in filtered_artifact_0_data_filter_4:
        for playbook_input_phishing_inbox_email_item in playbook_input_phishing_inbox_email:
            if filtered_artifact_0_item_filter_4[0] is not None and wrong_email_attached_format is not None:
                parameters.append({
                    "cc": "",
                    "to": filtered_artifact_0_item_filter_4[0],
                    "from": playbook_input_phishing_inbox_email_item[0],
                    "headers": headers_formatted_string,
                    "subject": subject_formatted_string,
                    "html_body": wrong_email_attached_format,
                    "context": {'artifact_id': filtered_artifact_0_item_filter_4[2]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send htmlemail", parameters=parameters, name="send_htmlemail_3", assets=["smtp"])

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Attached Suspicious Email"]
        ],
        conditions_dps=[
            ["artifact:*.name", "==", "Attached Suspicious Email"]
        ],
        name="decision_1:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    filter_5(action=action, success=success, container=container, results=results, handle=handle)

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