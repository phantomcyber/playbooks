"""
This playbook queries Active Directory for a list of users in the Administrators group and uses the results to update a Custom List. When the playbook is executed for the first time it will create a Generator asset that will automatically launch future executions once each hour.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_for_generator' block
    check_for_generator(container=container)

    return

"""
Check to see if there is already a Generator asset with the tag "track_active_directory_admin_users". This will be used to decide if a new Generator asset should be created.
"""
def check_for_generator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_for_generator() called')

    # collect data for 'check_for_generator' call

    parameters = []
    
    # build parameters list for 'check_for_generator' call
    parameters.append({
        'headers': "",
        'location': "/rest/asset?_filter_tags=[\"track_active_directory_admin_users\"]",
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['http'], callback=extract_response_body, name="check_for_generator")

    return

"""
Get a list of all the users in the "Administrators" group in Active Directory, which includes "Domain Admins" and "Enterprise Admins" by default.
"""
def get_users_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_users_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_users_1' call

    parameters = []
    
    # build parameters list for 'get_users_1' call
    parameters.append({
        'ph': "",
        'all_users': False,
        'object_name': "Administrators",
        'object_class': "group",
    })

    phantom.act(action="get users", parameters=parameters, assets=['domainctrl1'], callback=filter_1, name="get_users_1")

    return

"""
Ignore the returned SAM account names that are already in the custom list called "Active Directory Administrators".
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_users_1:action_result.data.*.samaccountname", "not in", "custom_list:Active Directory Administrators"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add the newly detected users to the custom list called "Active Directory Administrators".
"""
def update_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_custom_list() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:get_users_1:action_result.data.*.samaccountname'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.add_list("Active Directory Administrators", filtered_results_item_1_0)

    return

"""
Create the custom list called "Active Directory Administrators". This block should only be executed the first time this playbook is run.
"""
def create_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_custom_list() called')

    phantom.add_list("Active Directory Administrators", [])

    return

"""
Send an email to notify appropriate personnel of any new Administrators that were detected.
"""
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_email')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'cc': "",
        'to': "notifications@example.com",
        'bcc': "",
        'body': formatted_data_1,
        'from': "notifications@example.com",
        'headers': "",
        'subject': "New Admin Users",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=update_custom_list, name="send_email_1")

    return

"""
Decide whether this is the first execution of this playbook, in which case a new Generator and Custom List will be created. If the Generator already exists the actual Active Directory query will be run.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["track_active_directory_admin_users", "in", "extract_response_body:formatted_data"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_users_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_generator(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format a JSON object for creating a Generator asset to run the Active Directory check on a scheduled basis.

"""
def format_generator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_generator() called')
    
    input_parameter_0 = ""

    format_generator__generator = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    now_plus_minute = int(datetime.utcnow().strftime('%s')) + 60
    
    format_generator__generator = {
        "description": "A cronjob-style Generator to kick off the track_active_directory_admin_users Playbook",
        "name": "track_active_directory_admin_users_generator",
        "product_name": "Generator",
        "product_vendor": "Generic",
        "type": "generic",
        "tags": ["track_active_directory_admin_users"],
        "configuration": {
            "create_containers": "1",
            "create_artifacts": "1",
            "artifact_count_override": True,
            "container_tag": "track_active_directory_admin_users",
            "randomize_container_status": False,
            "container_prefix": "Track Active Directory Admin Users",
            "max_cef_per_artifact": "0",
            "min_cef_per_artifact": "0",
            "ingest": {
                "interval_mins": "60",
                "poll": True,
                "container_label": "events",
                "start_time_epoch_utc": None
            }
        }
    }
    
    format_generator__generator = json.dumps(format_generator__generator)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_generator:generator', value=json.dumps(format_generator__generator))
    create_generator(container=container)

    return

"""
Create a Generator asset by POSTing the desired configuration to the REST API of this Phantom instance. This block should only be executed the first time this playbook is run.
"""
def create_generator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_generator() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    format_generator__generator = json.loads(phantom.get_run_data(key='format_generator:generator'))
    # collect data for 'create_generator' call

    parameters = []
    
    # build parameters list for 'create_generator' call
    parameters.append({
        'body': format_generator__generator,
        'headers': "",
        'location': "/rest/asset",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['http'], callback=create_custom_list, name="create_generator")

    return

"""
Convert the returned HTTP response body into a flat string that can be used directly in a decision.
"""
def extract_response_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_response_body() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "check_for_generator:action_result.data.*.response_body",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="extract_response_body")

    decision_1(container=container)

    return

"""
Format a message for an email listing the new Administrators that were detected.
"""
def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email() called')
    
    template = """The Phantom playbook called track_active_directory_admin_users detected that the following new users were added to the Administrators group in Active Directory:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:get_users_1:action_result.data.*.samaccountname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    send_email_1(container=container)

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