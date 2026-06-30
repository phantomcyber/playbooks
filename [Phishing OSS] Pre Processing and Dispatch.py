"""
Splunk Global Security Phishing. This is the main orchestration playbook that coordinates the entire automation response workflow. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook__phishing_oss__phishing_attachment_filter_1' block
    playbook__phishing_oss__phishing_attachment_filter_1(container=container)

    return

@phantom.playbook_block()
def playbook__phishing_oss__phishing_attachment_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__phishing_attachment_filter_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Phishing Attachment Filter", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Phishing Attachment Filter", container=container, name="playbook__phishing_oss__phishing_attachment_filter_1", callback=playbook__phishing_oss__not_previous_thread_1)

    return


@phantom.playbook_block()
def playbook__phishing_oss__not_previous_thread_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__not_previous_thread_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Not Previous Thread", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Not Previous Thread", container=container, name="playbook__phishing_oss__not_previous_thread_1", callback=get_container_custom_data_key_6)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    tags_value = container.get("tags", None)

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["get_container_custom_data_key_6:custom_function_result.data.*.custom_key_value", "==", False],
            ["Previous Thread", "not in", tags_value]
        ],
        conditions_dps=[
            ["get_container_custom_data_key_6:custom_function_result.data.*.custom_key_value", "==", False],
            ["Previous Thread", "not in", "container:tags"]
        ],
        name="decision_1:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook__phishing_oss__acknowledgement_email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def playbook__phishing_oss__acknowledgement_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__acknowledgement_email_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Acknowledgement Email", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Acknowledgement Email", container=container, name="playbook__phishing_oss__acknowledgement_email_1", callback=playbook__phishing_oss__saa_enrich_1)

    return


@phantom.playbook_block()
def playbook__phishing_oss__saa_enrich_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__saa_enrich_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] SAA Enrich", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] SAA Enrich", container=container, name="playbook__phishing_oss__saa_enrich_1", callback=score_above_threshold)

    return


@phantom.playbook_block()
def score_above_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("score_above_threshold() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook__phishing_oss__saa_enrich_1:playbook_output:saa_score", ">=", 70]
        ],
        conditions_dps=[
            ["playbook__phishing_oss__saa_enrich_1:playbook_output:saa_score", ">=", 70]
        ],
        name="score_above_threshold:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook__phishing_oss__indicator_blocks_1(action=action, success=success, container=container, results=results, handle=handle)
        playbook__phishing_oss__quarantine_device_1(action=action, success=success, container=container, results=results, handle=handle)
        playbook__phishing_oss__tip_addition_1(action=action, success=success, container=container, results=results, handle=handle)
        set_container_custom_data_dey_value_7(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def playbook__phishing_oss__indicator_blocks_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__indicator_blocks_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Indicator Blocks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Indicator Blocks", container=container)

    return


@phantom.playbook_block()
def playbook__phishing_oss__quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__quarantine_device_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Quarantine Device", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Quarantine Device", container=container)

    return


@phantom.playbook_block()
def playbook__phishing_oss__tip_addition_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__tip_addition_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] TIP Addition", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] TIP Addition", container=container)

    return


@phantom.playbook_block()
def playbook__phishing_oss__purge_dispatcher_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__purge_dispatcher_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/[Phishing OSS] Purge Dispatcher", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/[Phishing OSS] Purge Dispatcher", container=container)

    return


@phantom.playbook_block()
def filter_attached_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_attached_email() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Attached Suspicious Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Attached Suspicious Email", "in", "artifact:*.name"]
        ],
        name="filter_attached_email:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_out_auto_replies(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_out_auto_replies(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_out_auto_replies() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:phishing_inbox_email", "not in", "filtered-data:filter_attached_email:condition_1:artifact:*.cef.fromEmail"]
        ],
        conditions_dps=[
            ["playbook_input:phishing_inbox_email", "not in", "filtered-data:filter_attached_email:condition_1:artifact:*.cef.fromEmail"]
        ],
        name="filter_out_auto_replies:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        identify_campaign(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def identify_campaign(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("identify_campaign() called")

    filtered_artifact_0_data_filter_out_auto_replies = phantom.collect2(container=container, datapath=["filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.decodedSubject","filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.Message-ID","filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.Date"])

    filtered_artifact_0__cef_emailheaders_decodedsubject = [item[0] for item in filtered_artifact_0_data_filter_out_auto_replies]
    filtered_artifact_0__cef_fromemail = [item[1] for item in filtered_artifact_0_data_filter_out_auto_replies]
    filtered_artifact_0__cef_emailheaders_message_id = [item[2] for item in filtered_artifact_0_data_filter_out_auto_replies]
    filtered_artifact_0__cef_emailheaders_date = [item[3] for item in filtered_artifact_0_data_filter_out_auto_replies]

    identify_campaign__campaignname = None
    identify_campaign__sender = None
    identify_campaign__subject = None
    identify_campaign__message_id = None
    identify_campaign__date = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    
    phantom.error(filtered_artifact_0__cef_emailheaders_decodedsubject)
    subject=str(filtered_artifact_0__cef_emailheaders_decodedsubject[0].encode('ascii','ignore').decode('ascii'))
    sender=str(filtered_artifact_0__cef_fromemail[0])
    message_id_paths = phantom.collect2(container=container, datapath=[ 'filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.Message-ID','filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.Message-Id'])
    phantom.debug(message_id_paths)
    message_ids=message_id_paths[0]
    phantom.error(message_ids)
    
    message_id=str(next(item for item in message_ids if item is not None and item != 'null'))
    
    date=str(filtered_artifact_0__cef_emailheaders_date[0])
    
    
    match=re.search(r'[\w\.-]+@[\w\.-]+', sender).group(0)       
    sender=match
    phantom.error("SENDER IS: "+sender)

    subject=subject.replace("\r","")
    subject=subject.replace("\n","")
    subject=subject.replace("\t","")
    #remove enocde to ascii in python3
    #subject=subject.decode('ascii','ignore').encode("ascii")
    l=subject.split(']')
    subject=l[len(l)-1].strip()
    #subject=' '.join(word for word in subject.split(' ') if not word.startswith('['))  
    rule= re.compile("(FW|RE|FWD|Fwd|fwd|re|Re).*:")
    rule.sub("",subject)
    phantom.error("SUBJECT IS: "+subject)
             
    phantom.error("DATE IS: "+date)         
    phantom.error("MESSAGE_ID IS: "+message_id)         
      
    identify_campaign__campaignname="|Sub: "+subject+"|Sender: "+sender+"|Date: "+date+"|ID: "+message_id+"|"
    phantom.error("CampaignName: "+identify_campaign__campaignname)
    identify_campaign__sender=sender
    identify_campaign__subject=subject
    identify_campaign__message_id=message_id
    identify_campaign__date=date
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="identify_campaign__inputs:0:filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.decodedSubject", value=json.dumps(filtered_artifact_0__cef_emailheaders_decodedsubject))
    phantom.save_block_result(key="identify_campaign__inputs:1:filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.fromEmail", value=json.dumps(filtered_artifact_0__cef_fromemail))
    phantom.save_block_result(key="identify_campaign__inputs:2:filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.Message-ID", value=json.dumps(filtered_artifact_0__cef_emailheaders_message_id))
    phantom.save_block_result(key="identify_campaign__inputs:3:filtered-data:filter_out_auto_replies:condition_1:artifact:*.cef.emailHeaders.Date", value=json.dumps(filtered_artifact_0__cef_emailheaders_date))

    phantom.save_block_result(key="identify_campaign:campaignname", value=json.dumps(identify_campaign__campaignname))
    phantom.save_block_result(key="identify_campaign:sender", value=json.dumps(identify_campaign__sender))
    phantom.save_block_result(key="identify_campaign:subject", value=json.dumps(identify_campaign__subject))
    phantom.save_block_result(key="identify_campaign:message_id", value=json.dumps(identify_campaign__message_id))
    phantom.save_block_result(key="identify_campaign:date", value=json.dumps(identify_campaign__date))

    phantom.save_block_result(key="identify_campaign_called", value="True")

    set_container_custom_data_dey_value_8(container=container)

    return


@phantom.playbook_block()
def get_container_custom_data_key_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_container_custom_data_key_6() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "PreviousThreadFlag",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/get_container_custom_data_key", parameters=parameters, name="get_container_custom_data_key_6", callback=decision_1)

    return


@phantom.playbook_block()
def set_container_custom_data_dey_value_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_container_custom_data_dey_value_7() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "purge_action",
        "custom_value": "purge",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/set_container_custom_data_dey_value", parameters=parameters, name="set_container_custom_data_dey_value_7", callback=filter_attached_email)

    return


@phantom.playbook_block()
def set_container_custom_data_dey_value_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_container_custom_data_dey_value_8() called")

    id_value = container.get("id", None)
    identify_campaign__subject = json.loads(_ if (_ := phantom.get_run_data(key="identify_campaign:subject")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "email_campaign_subject",
        "custom_value": identify_campaign__subject,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/set_container_custom_data_dey_value", parameters=parameters, name="set_container_custom_data_dey_value_8", callback=set_container_custom_data_dey_value_9)

    return


@phantom.playbook_block()
def set_container_custom_data_dey_value_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_container_custom_data_dey_value_9() called")

    id_value = container.get("id", None)
    identify_campaign__sender = json.loads(_ if (_ := phantom.get_run_data(key="identify_campaign:sender")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "container_id": id_value,
        "custom_key": "email_campaign_sender",
        "custom_value": identify_campaign__sender,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/set_container_custom_data_dey_value", parameters=parameters, name="set_container_custom_data_dey_value_9", callback=playbook__phishing_oss__purge_dispatcher_1)

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