"""
This playbook responds to Recorded Future monitoring of leaked credentials exposed on the internet. The accounts are verified to be enabled/disabled or if they exist in the LDAP environment.\n\nThen, a manual prompt to &#39;soft reset&#39; the account at next logon is issued.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_artifacts' block
    filter_artifacts(container=container)

    return

@phantom.playbook_block()
def filter_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_artifacts() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["EMAIL", "in", "artifact:*.name"]
        ],
        name="filter_artifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_account_ldap_attributes(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_account_ldap_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_account_ldap_attributes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_artifacts = phantom.collect2(container=container, datapath=["filtered-data:filter_artifacts:condition_1:artifact:*.cef.email","filtered-data:filter_artifacts:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'get_account_ldap_attributes' call
    for filtered_artifact_0_item_filter_artifacts in filtered_artifact_0_data_filter_artifacts:
        if filtered_artifact_0_item_filter_artifacts[0] is not None:
            parameters.append({
                "attributes": "sAMAccountName;pwdLastSet;userAccountControl;mail",
                "principals": filtered_artifact_0_item_filter_artifacts[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_artifacts[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get attributes", parameters=parameters, name="get_account_ldap_attributes", assets=["ldap"], callback=filter_active_accounts)

    return


@phantom.playbook_block()
def filter_active_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_active_accounts() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_account_ldap_attributes:action_result.status", "!=", "failed"],
            ["get_account_ldap_attributes:action_result.data.*.samaccountname", "!=", ""],
            ["get_account_ldap_attributes:action_result.summary.state", "==", "Enabled"]
        ],
        name="filter_active_accounts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_analyst(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def soft_reset_password(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("soft_reset_password() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_active_accounts = phantom.collect2(container=container, datapath=["filtered-data:filter_active_accounts:condition_1:get_account_ldap_attributes:action_result.data.*.samaccountname"])

    parameters = []

    # build parameters list for 'soft_reset_password' call
    for filtered_result_0_item_filter_active_accounts in filtered_result_0_data_filter_active_accounts:
        if filtered_result_0_item_filter_active_accounts[0] is not None:
            parameters.append({
                "user": filtered_result_0_item_filter_active_accounts[0],
                "use_samaccountname": True,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("reset password", parameters=parameters, name="soft_reset_password", assets=["ldap"])

    return


@phantom.playbook_block()
def prompt_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_analyst() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """The following user accounts have recently had their credentials exposed on the internet:\n\n{0}\n\nWould you like to force the users to reset their password at next logon or inform the user via email?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_active_accounts:condition_1:get_account_ldap_attributes:action_result.data.*.mail"
    ]

    # responses
    response_types = [
        {
            "prompt": "Reset password at next logon?",
            "options": {
                "type": "list",
                "choices": [
                    "Soft reset",
                    "Email user"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_analyst", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.0", "==", "Soft reset"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        soft_reset_password(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_email(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email() called")

    template = """We have found the account credentials belonging to your email address on the internet. We have omitted the password in this email for security reasons. \n\nPlease reset your password as soon as possible.\n\nSincerely,\nSecurity Operations"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    email_compromised_user(container=container)

    return


@phantom.playbook_block()
def email_compromised_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_compromised_user() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_result_0_data_filter_active_accounts = phantom.collect2(container=container, datapath=["filtered-data:filter_active_accounts:condition_1:get_account_ldap_attributes:action_result.data.*.mail"])
    format_email = phantom.get_format_data(name="format_email")

    parameters = []

    # build parameters list for 'email_compromised_user' call
    for filtered_result_0_item_filter_active_accounts in filtered_result_0_data_filter_active_accounts:
        if filtered_result_0_item_filter_active_accounts[0] is not None and format_email is not None:
            parameters.append({
                "to": filtered_result_0_item_filter_active_accounts[0],
                "subject": "Compromised Account",
                "body": format_email,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="email_compromised_user", assets=["smtp"])

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