"""
This playbook orchestrates bulk email purge operations across multiple users who received a phishing email. It&#39;s the coordinator that manages the &quot;Purge Worker&quot; playbook for each affected recipient.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_email_sender' block
    get_email_sender(container=container)

    return

@phantom.playbook_block()
def input_validation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_validation() called")

    get_email_subject_data = phantom.collect2(container=container, datapath=["get_email_subject:custom_function_result.data.*.custom_key_value"])
    get_email_sender_data = phantom.collect2(container=container, datapath=["get_email_sender:custom_function_result.data.*.custom_key_value"])
    get_action_data = phantom.collect2(container=container, datapath=["get_action:custom_function_result.data.*.custom_key_value"])

    get_email_subject_data___custom_key_value = [item[0] for item in get_email_subject_data]
    get_email_sender_data___custom_key_value = [item[0] for item in get_email_sender_data]
    get_action_data___custom_key_value = [item[0] for item in get_action_data]

    input_validation__email_subject = None
    input_validation__email_sender = None
    input_validation__action = None
    input_validation__inputvalidflag = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    input_validation__action=get_action_data___custom_key_value[0]
    input_validation__email_sender=get_email_sender_data___custom_key_value[0]
    input_validation__email_subject =get_email_subject_data___custom_key_value[0]
    
    input_validation__inputvalidflag = False
    
    
    #input_validation__action="unpurge"
    #input_validation__email_sender="purge-unpurge-test@splunk.com"
    #input_validation__email_subject ="10Apr_phishingTest_naman_2"
    
    if input_validation__action is not None and input_validation__action!="" and input_validation__email_sender is not None and input_validation__email_sender!="" and input_validation__email_sender is not None and input_validation__email_sender!="":
        input_validation__inputvalidflag=True
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="input_validation__inputs:0:get_email_subject:custom_function_result.data.*.custom_key_value", value=json.dumps(get_email_subject_data___custom_key_value))
    phantom.save_block_result(key="input_validation__inputs:1:get_email_sender:custom_function_result.data.*.custom_key_value", value=json.dumps(get_email_sender_data___custom_key_value))
    phantom.save_block_result(key="input_validation__inputs:2:get_action:custom_function_result.data.*.custom_key_value", value=json.dumps(get_action_data___custom_key_value))

    phantom.save_block_result(key="input_validation:email_subject", value=json.dumps(input_validation__email_subject))
    phantom.save_block_result(key="input_validation:email_sender", value=json.dumps(input_validation__email_sender))
    phantom.save_block_result(key="input_validation:action", value=json.dumps(input_validation__action))
    phantom.save_block_result(key="input_validation:inputvalidflag", value=json.dumps(input_validation__inputvalidflag))

    phantom.save_block_result(key="input_validation_called", value="True")

    decision_2(container=container)

    return


@phantom.playbook_block()
def stub_for_spl_scope_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("stub_for_spl_scope_playbook() called")

    playbook__phishing_pond__campaign_recipients_output_1_output_emails_list = phantom.collect2(container=container, datapath=["playbook__phishing_pond__campaign_recipients_output_1:playbook_output:emails_list"])

    playbook__phishing_pond__campaign_recipients_output_1_output_emails_list_values = [item[0] for item in playbook__phishing_pond__campaign_recipients_output_1_output_emails_list]

    stub_for_spl_scope_playbook__recipients_list = None
    stub_for_spl_scope_playbook__formatted_recipient_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    
    stub_for_spl_scope_playbook__recipients_list = playbook__phishing_pond__campaign_recipients_output_1_output_emails_list_values
    
    phantom.debug("Recipients who received the email \n : \n {}".format(stub_for_spl_scope_playbook__recipients_list))
    
    
    stub_for_spl_scope_playbook__formatted_recipient_list=" \n".join(stub_for_spl_scope_playbook__recipients_list)
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="stub_for_spl_scope_playbook__inputs:0:playbook__phishing_pond__campaign_recipients_output_1:playbook_output:emails_list", value=json.dumps(playbook__phishing_pond__campaign_recipients_output_1_output_emails_list_values))

    phantom.save_block_result(key="stub_for_spl_scope_playbook:recipients_list", value=json.dumps(stub_for_spl_scope_playbook__recipients_list))
    phantom.save_block_result(key="stub_for_spl_scope_playbook:formatted_recipient_list", value=json.dumps(stub_for_spl_scope_playbook__formatted_recipient_list))

    phantom.save_block_result(key="stub_for_spl_scope_playbook_called", value="True")

    create_purge_processing_list(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["input_validation:custom_function:action", "==", "purge"]
        ],
        conditions_dps=[
            ["input_validation:custom_function:action", "==", "purge"]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        playbook__phishing_oss__scope_campaign_recipients_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["input_validation:custom_function:action", "==", "unpurge"]
        ],
        conditions_dps=[
            ["input_validation:custom_function:action", "==", "unpurge"]
        ],
        name="decision_1:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["input_validation:custom_function:action", "==", "cleanup"]
        ],
        conditions_dps=[
            ["input_validation:custom_function:action", "==", "cleanup"]
        ],
        name="decision_1:condition_3",
        delimiter=None)

    # call connected blocks if condition 3 matched
    if found_match_3:
        return

    return


@phantom.playbook_block()
def create_purge_processing_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_purge_processing_list() called")

    stub_for_spl_scope_playbook__recipients_list = json.loads(_ if (_ := phantom.get_run_data(key="stub_for_spl_scope_playbook:recipients_list")) != "" else "null")  # pylint: disable=used-before-assignment
    input_validation__email_sender = json.loads(_ if (_ := phantom.get_run_data(key="input_validation:email_sender")) != "" else "null")  # pylint: disable=used-before-assignment
    input_validation__email_subject = json.loads(_ if (_ := phantom.get_run_data(key="input_validation:email_subject")) != "" else "null")  # pylint: disable=used-before-assignment
    email_purge_lookup__email_purge_dict_list = json.loads(_ if (_ := phantom.get_run_data(key="email_purge_lookup:email_purge_dict_list")) != "" else "null")  # pylint: disable=used-before-assignment

    create_purge_processing_list__purge_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    from datetime import datetime
    processing_list=[]
    add_list=[]
    update_list=[]
    state=email_purge_lookup__email_purge_dict_list[1:]
    
    phantom.debug("state is :\n {}".format(state))
    
    
    for splunker in stub_for_spl_scope_playbook__recipients_list:
        
        splunker_list=[i for i in state if i["splunker_recipient"]==splunker and i["sender"]==input_validation__email_sender and i["subject"]==input_validation__email_subject] # list only this splunker
        phantom.debug("SPLUNKER LIST is {}".format(splunker_list))
        if splunker_list:
            for item in splunker_list:
                if "purged" or "unpurged" in item["status"]:
                    pass
                else:
                    update_list.append({k:item[k] for k in item.keys()-["row_num"]})
        else:
            phantom.debug("NO SPLUNKER LIST ADD LIST ")
            add_list.append(
                {
                    "sender": input_validation__email_sender,
                    "subject": input_validation__email_subject,
                    "splunker_recipient": splunker,
                    "date_added": datetime.utcnow().date().strftime("%m/%d/%Y"),#"01/17/2024",# TO DO current date in mm/dd/yyyy
                    "status": "added"
                }
            )
                
        
        # for item in email_purge_lookup__email_purge_dict_list[1:]:
#             if splunker in item["splunker_recipient"] and input_validation__email_sender in item["sender"] and input_validation__email_subject in item["subject"]:
#                 if "purged" in item["status"]:
#                     phantom.debug("previously procesed but added")
#                     phantom.debug(item)
#                     pass
#                 else:
#                     phantom.debug("not previously procesed but added")
#                     phantom.debug(item)
#                     update_list.append({k:item[k] for k in item.keys()-["row_num"]})
#             if not (splunker  in item["splunker_recipient"] and input_validation__email_sender  in item["sender"] and input_validation__email_subject not in item["subject"]):
#                 phantom.debug("not in state table but in scope recipients")
#                 phantom.debug(item)
#                 add_list.append(
#                     {
#                         "sender": input_validation__email_sender,
#                         "subject": input_validation__email_subject,
#                         "splunker_recipient": splunker,
#                         "date_added": datetime.utcnow().date().strftime("%m/%d/%Y"),#"01/17/2024",# TO DO current date in mm/dd/yyyy
#                         "status": "added"
#                     }
#                 )
        
    phantom.debug("Update list :\n{}".format(update_list))
    phantom.debug("Add list :\n{}".format(add_list))
    add_list.extend(update_list)
    #phantom.debug(add_list)
    processing_list.extend(add_list)
    create_purge_processing_list__purge_list = processing_list
    
    phantom.debug(create_purge_processing_list__purge_list)
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="create_purge_processing_list__inputs:0:stub_for_spl_scope_playbook:custom_function:recipients_list", value=json.dumps(stub_for_spl_scope_playbook__recipients_list))
    phantom.save_block_result(key="create_purge_processing_list__inputs:1:input_validation:custom_function:email_sender", value=json.dumps(input_validation__email_sender))
    phantom.save_block_result(key="create_purge_processing_list__inputs:2:input_validation:custom_function:email_subject", value=json.dumps(input_validation__email_subject))
    phantom.save_block_result(key="create_purge_processing_list__inputs:3:email_purge_lookup:custom_function:email_purge_dict_list", value=json.dumps(email_purge_lookup__email_purge_dict_list))

    phantom.save_block_result(key="create_purge_processing_list:purge_list", value=json.dumps(create_purge_processing_list__purge_list))

    phantom.save_block_result(key="create_purge_processing_list_called", value="True")

    dispatch_purge(container=container)

    return


@phantom.playbook_block()
def custom_list_enumerate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("custom_list_enumerate_1() called")

    parameters = []

    parameters.append({
        "custom_list": "email_purge_lookup",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/custom_list_enumerate", parameters=parameters, name="custom_list_enumerate_1", callback=email_purge_lookup)

    return


@phantom.playbook_block()
def email_purge_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("email_purge_lookup() called")

    custom_list_enumerate_1__result = phantom.collect2(container=container, datapath=["custom_list_enumerate_1:custom_function_result.data"])

    custom_list_enumerate_1_data = [item[0] for item in custom_list_enumerate_1__result]

    email_purge_lookup__email_purge_lookup = None
    email_purge_lookup__email_purge_dict_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    email_purge_lookup__email_purge_dict_list= custom_list_enumerate_1_data[0]
    phantom.debug(email_purge_lookup__email_purge_dict_list)
    
    key=email_purge_lookup__email_purge_dict_list[0]
    keys=[key.get("column_0"),key.get("column_1"),key.get("column_2"),key.get("column_3"),key.get("column_4")]
    
    for item in email_purge_lookup__email_purge_dict_list:
        item[keys[0]]=item.pop("column_0")
        item[keys[1]]=item.pop("column_1")
        item[keys[2]]=item.pop("column_2")  
        item[keys[3]]=item.pop("column_3")  
        item[keys[4]]=item.pop("column_4")
        
    phantom.debug(email_purge_lookup__email_purge_dict_list[1:])
    
    
    
    success, message, execs = phantom.get_list(list_name='email_purge_lookup')

    phantom.debug(
        'phantom.get_list results: success: {}, message: {}, execs: {}'\
        .format(success, message, execs)
    )
    email_purge_lookup__email_purge_lookup = execs
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="email_purge_lookup__inputs:0:custom_list_enumerate_1:custom_function_result.data", value=json.dumps(custom_list_enumerate_1_data))

    phantom.save_block_result(key="email_purge_lookup:email_purge_lookup", value=json.dumps(email_purge_lookup__email_purge_lookup))
    phantom.save_block_result(key="email_purge_lookup:email_purge_dict_list", value=json.dumps(email_purge_lookup__email_purge_dict_list))

    phantom.save_block_result(key="email_purge_lookup_called", value="True")

    decision_1(container=container)

    return


@phantom.playbook_block()
def dispatch_purge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("dispatch_purge() called")

    create_purge_processing_list__purge_list = json.loads(_ if (_ := phantom.get_run_data(key="create_purge_processing_list:purge_list")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    for item in create_purge_processing_list__purge_list:
        inputs = {
            "splunker_email": item["splunker_recipient"],
            "email_subject": item["subject"],
            "email_sender": item["sender"],
        }

        # call playbook "local/[PP] UnPurge worker", returns the playbook_run_id
        playbook_run_id = phantom.playbook("sgs-soarcloud-gso-dev/[Phishing OSS] Purge Worker", container=container, inputs=inputs)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="dispatch_purge__inputs:0:create_purge_processing_list:custom_function:purge_list", value=json.dumps(create_purge_processing_list__purge_list))

    phantom.save_block_result(key="dispatch_purge_called", value="True")

    update_purged_lookup(container=container)

    return


@phantom.playbook_block()
def update_purged_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_purged_lookup() called")

    create_purge_processing_list__purge_list = json.loads(_ if (_ := phantom.get_run_data(key="create_purge_processing_list:purge_list")) != "" else "null")  # pylint: disable=used-before-assignment
    email_purge_lookup__email_purge_lookup = json.loads(_ if (_ := phantom.get_run_data(key="email_purge_lookup:email_purge_lookup")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(create_purge_processing_list__purge_list)
    
    purge_dict_list = [{k: "purged" if k == "status" else v for k, v in d.items()} for d in create_purge_processing_list__purge_list]
    #change status from added to purged
    phantom.debug(purge_dict_list)
    
    #purged_list= [list(create_purge_processing_list__purge_list[0].keys())] +[list(d.values()) for d in create_purge_processing_list__purge_list]
    
    # Extract header from the first dictionary
    #header = list(create_purge_processing_list__purge_list[0].keys())

    # Create a list of lists with values in the same order as keys
    #purged_list = [header] + [[d[key] for key in header] for d in create_purge_processing_list__purge_list]
    
    #phantom.debug(purged_list)
    
    phantom.debug(email_purge_lookup__email_purge_lookup)
    
    #list_to_remove_from_lookup=[]
    #for item in purged_list:
        #item_user_subject_sender_list_to_update = [i for i in email_purge_lookup__email_purge_lookup if i[0]== item[0] and  i[1]== item[1] and  i[2]== item[2]  and i[4]!= item[4]]
        #list_to_remove_from_lookup.extend(item_user_subject_sender_list_to_update)
        
    #update_removed_list=[i for i in email_purge_lookup__email_purge_lookup if i not in list_to_remove_from_lookup]
    
    #difference = [item for item in purged_list if item not in email_purge_lookup__email_purge_lookup]
    
    #update_added_list=update_removed_list+difference
    
    #phantom.debug(update_added_list)
    
    keys=email_purge_lookup__email_purge_lookup[0]

    state_dict_list = [dict(zip(keys, values)) for values in email_purge_lookup__email_purge_lookup[1:]]
    
    purge_set_dict_list=state_dict_list+purge_dict_list

    header = list(purge_set_dict_list[0].keys())
    #    Create a list of lists with values in the same order as keys
    purge_set_list = [header] + [[d[key] for key in header] for d in purge_set_dict_list]
    
    
    success, message = phantom.set_list(list_name='email_purge_lookup', values=purge_set_list)
    
    phantom.debug('phantom.set_list results: success: {}, message: {}'.format(success, message))
    
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="update_purged_lookup__inputs:0:create_purge_processing_list:custom_function:purge_list", value=json.dumps(create_purge_processing_list__purge_list))
    phantom.save_block_result(key="update_purged_lookup__inputs:1:email_purge_lookup:custom_function:email_purge_lookup", value=json.dumps(email_purge_lookup__email_purge_lookup))

    phantom.save_block_result(key="update_purged_lookup_called", value="True")

    return


@phantom.playbook_block()
def get_email_sender(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_email_sender() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "custom_key": "email_campaign_sender",
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="sgs-soarcloud-gso-dev/Get_Container_Custom_Data_Key", parameters=parameters, name="get_email_sender", callback=get_email_subject)

    return


@phantom.playbook_block()
def get_email_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_email_subject() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "custom_key": "email_campaign_subject",
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="sgs-soarcloud-gso-dev/Get_Container_Custom_Data_Key", parameters=parameters, name="get_email_subject", callback=get_action)

    return


@phantom.playbook_block()
def get_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_action() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "custom_key": "purge_action",
        "container_id": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="sgs-soarcloud-gso-dev/Get_Container_Custom_Data_Key", parameters=parameters, name="get_action", callback=input_validation)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["input_validation:custom_function:inputvalidflag", "==", True]
        ],
        conditions_dps=[
            ["input_validation:custom_function:inputvalidflag", "==", True]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        custom_list_enumerate_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def playbook__phishing_oss__scope_campaign_recipients_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook__phishing_oss__scope_campaign_recipients_1() called")

    input_validation__email_sender = json.loads(_ if (_ := phantom.get_run_data(key="input_validation:email_sender")) != "" else "null")  # pylint: disable=used-before-assignment
    input_validation__email_subject = json.loads(_ if (_ := phantom.get_run_data(key="input_validation:email_subject")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "sender": input_validation__email_sender,
        "subject": input_validation__email_subject,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "sgs-soarcloud-gso-dev/[Phishing OSS] Scope Campaign recipients", returns the playbook_run_id
    playbook_run_id = phantom.playbook("sgs-soarcloud-gso-dev/[Phishing OSS] Scope Campaign recipients", container=container, name="playbook__phishing_oss__scope_campaign_recipients_1", callback=stub_for_spl_scope_playbook, inputs=inputs)

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