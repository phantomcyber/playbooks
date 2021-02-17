"""
This playbook responds to Recorded Future monitoring of leaked credentials exposed on the internet. The accounts are deduplicated, verified internally, investigated, and passed on to an account reset playbook for further action.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

from random import randint
from random import shuffle


# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'rf_get_rule_id_by_name' block
    rf_get_rule_id_by_name(container=container)

    return

"""
Formats the alert data to a nice format for adding a note
"""
def format_victims_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_victims_list() called')
    
    template = """Recorded Future is alerting on probable leaked credentials. This contains the complete list.
<p>
Alert: 
{0}
</p>
<p>
More information: 
 {1}
</p>
<p>
Leaked Email addresses:
%%
<br>address: {2}
%%
</p>"""

    # parameter list for template variable replacement
    parameters = [
        "rf_get_rule_data:action_result.data.*.alerts.*.alert.content.title",
        "rf_get_rule_data:action_result.data.*.alerts.*.alert.content.url",
        "dedup_accounts:custom_function:dedup_email",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_victims_list")

    add_note_5(container=container)

    return

"""
Query for alerts from the last 24 hours using the returned alert rule ID
"""
def rf_get_rule_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('rf_get_rule_data() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'rf_get_rule_data' call
    results_data_1 = phantom.collect2(container=container, datapath=['rf_get_rule_id_by_name:action_result.data.*.rule.id', 'rf_get_rule_id_by_name:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'rf_get_rule_data' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'rule_id': results_item_1[0],
                'timeframe': "-24h to now",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="alert data lookup", parameters=parameters, assets=['recorded_future'], callback=dedup_accounts, name="rf_get_rule_data", parent_action=action)

    return

"""
Uses the name of a Recorded Future Alert Rule to fetch the rule ID
"""
def rf_get_rule_id_by_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('rf_get_rule_id_by_name() called')

    # collect data for 'rf_get_rule_id_by_name' call

    parameters = []
    
    # build parameters list for 'rf_get_rule_id_by_name' call
    parameters.append({
        'rule_name': "Leaked Credential Monitoring",
    })

    phantom.act(action="alert rule lookup", parameters=parameters, assets=['recorded_future'], callback=rf_get_rule_data, name="rf_get_rule_id_by_name")

    return

"""
Finds directory users with matching mail attributes
"""
def get_affected_ad_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_affected_ad_users() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_affected_ad_users' call
    formatted_data_1 = phantom.get_format_data(name='convert_to_list__as_list')

    parameters = []
    
    # build parameters list for 'get_affected_ad_users' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'fields': "sAMAccountName,pwdLastSet,userAccountControl,mail",
            'username': formatted_part_1,
            'attribute': "mail",
        })

    phantom.act(action="get user attributes", parameters=parameters, app={ "name": 'LDAP' }, callback=get_active_ad_users, name="get_affected_ad_users")

    return

"""
Filters down to users that both exist in the directory and are enabled
"""
def get_active_ad_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_active_ad_users() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_affected_ad_users:action_result.status", "!=", "failed"],
            ["get_affected_ad_users:action_result.data.*.samaccountname", "!=", ""],
            ["get_affected_ad_users:action_result.summary.state", "==", "Enabled"],
        ],
        logical_operator='and',
        name="get_active_ad_users:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        launch_reset_playbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Deduplicates any accounts in the list provided by Recorded Future
"""
def dedup_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dedup_accounts() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['rf_get_rule_data:action_result.data.*.alerts.*.alert.content.entities.*.documents.*.references.*.entities.*.name', 'rf_get_rule_data:action_result.data.*.alerts.*.alert.content.entities.*.documents.*.references.*.entities.*.type'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    dedup_accounts__dedup_email = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # NOTE: Dedups the entities of type EmailAddress for downstream usage.
    dedup_accounts__dedup_email = []
    if len(results_item_1_0) == len(results_item_1_1):
        for i in range(len(results_item_1_0)):
            if results_item_1_1[i] == "EmailAddress":
                dedup_accounts__dedup_email.append(results_item_1_0[i])
    else:
        phantom.debug("[DEBUG] Inconsistent Lengths.")
    
    dedup_accounts__dedup_email = list(set(dedup_accounts__dedup_email))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='dedup_accounts:dedup_email', value=json.dumps(dedup_accounts__dedup_email))
    convert_to_list(container=container)
    format_victims_list(container=container)

    return

"""
Converts the custom code block to an iterable list
"""
def convert_to_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('convert_to_list() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "dedup_accounts:custom_function:dedup_email",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="convert_to_list")

    get_affected_ad_users(container=container)

    return

"""
Adds a note to the container with the full list provided by Recorded Future as a reference
"""
def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_victims_list')

    note_title = "add rf complete list note"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Creates new compromised_credential artifacts for each user found. Starts the activedirectory_reset_password playbook to potentially reset the AD account for each artifact created
"""
def launch_reset_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('launch_reset_playbook() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:get_active_ad_users:condition_1:get_affected_ad_users:action_result.data.*.samaccountname'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    for r in filtered_results_item_1_0:
        phantom.debug("[DEBUG]: account = {}".format(r))
        phantom.add_artifact(container=container,
                             raw_data={'compromisedUserName':r},
                             cef_data={'compromisedUserName':r},
                             label='compromised_account',
                             name='compromised account ' + r,
                             identifier=None,
                             artifact_type='user name',
                             severity='high',
                             run_automation=True)
        
        # calling the playbook here is necessary because artifacts are not evaluated while
        # this code block runs. Consequently, all artifacts are fired as a list instead of
        # individually without this next call to playbook().
        phantom.playbook(playbook='local/activedirectory_reset_password',
                         container=container,
                         show_debug=True)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return