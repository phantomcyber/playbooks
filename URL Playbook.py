"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'virustotal_check' block
    virustotal_check(container=container)

    return

@phantom.playbook_block()
def virustotal_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("virustotal_check() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'virustotal_check' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="virustotal_check", assets=["virustotal "], callback=metadefender_sandbox_check)

    return


@phantom.playbook_block()
def metadefender_sandbox_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("metadefender_sandbox_check() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'metadefender_sandbox_check' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="metadefender_sandbox_check", assets=["metadefender sandbox"], callback=joe_sandbox_check)

    return


@phantom.playbook_block()
def joe_sandbox_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("joe_sandbox_check() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'joe_sandbox_check' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="joe_sandbox_check", assets=["joe sandbox"], callback=falcon_sandbox_check)

    return


@phantom.playbook_block()
def falcon_sandbox_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("falcon_sandbox_check() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])
    joe_sandbox_check_result_data = phantom.collect2(container=container, datapath=["joe_sandbox_check:action_result.parameter.context.artifact_id","joe_sandbox_check:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'falcon_sandbox_check' call
    for container_artifact_item in container_artifact_data:
        for joe_sandbox_check_result_item in joe_sandbox_check_result_data:
            if container_artifact_item[0] is not None and joe_sandbox_check_result_item[0] is not None:
                parameters.append({
                    "url": container_artifact_item[0],
                    "environment_id": joe_sandbox_check_result_item[0],
                    "context": {'artifact_id': joe_sandbox_check_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="falcon_sandbox_check", assets=["falcon sandbox"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["virustotal_check:action_result.data.*.attributes.last_analysis_stats.malicious", "==", 3],
            ["virustotal_check:action_result.data.*.attributes.total_votes.malicious", "==", 3],
            ["virustotal_check:action_result.summary.malicious", "==", 3],
            ["virustotal_check:action_result.data.*.attributes.last_analysis_stats.suspicious", "==", 3],
            ["virustotal_check:action_result.summary.suspicious", "==", 3]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def block_url_on_proxy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_url_on_proxy() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'block_url_on_proxy' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block url", parameters=parameters, name="block_url_on_proxy", assets=["zscaler proxy"], callback=join_create_incident_ticket_via_jira)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'else' condition 2
    join_check_referer_url(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def query_splunk_to_list_affected_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("query_splunk_to_list_affected_users() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""source=\"test.csv\" url=\"https://maliciousurl.com\"\n| dedup username\n| table username\n\n""",
        parameters=[
            ""
        ])

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "search",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="query_splunk_to_list_affected_users", assets=["splunk"], callback=resolve_affected_machines_using_ldap)

    return


@phantom.playbook_block()
def resolve_affected_machines_using_ldap(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("resolve_affected_machines_using_ldap() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    inputs_data_0 = phantom.collect2(container=container, datapath=["query_splunk_to_list_affected_users:artifact:*.cef.sourceUserName","query_splunk_to_list_affected_users:artifact:*.id"])

    parameters = []

    # build parameters list for 'resolve_affected_machines_using_ldap' call
    for inputs_item_0 in inputs_data_0:
        if inputs_item_0[0] is not None:
            parameters.append({
                "filter": inputs_item_0[0],
                "attributes": "sAMAccountName",
                "context": {'artifact_id': inputs_item_0[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="resolve_affected_machines_using_ldap", assets=["test"], callback=scan_the_machines_of_affected_users)

    return


@phantom.playbook_block()
def scan_the_machines_of_affected_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("scan_the_machines_of_affected_users() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "comment": "test",
        "timeout": 30,
        "device_id": "test",
        "scan_type": "Quick",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("scan device", parameters=parameters, name="scan_the_machines_of_affected_users", assets=["microsoft defender for endpoint (edr)"], callback=acquire_recent_downloads)

    return


@phantom.playbook_block()
def acquire_recent_downloads(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("acquire_recent_downloads() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "file_path": "C:\\Users\\<Username>\\Downloads\\",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="acquire_recent_downloads", assets=["microsoft defender for endpoint (edr)"], callback=acquire_browser_history)

    return


@phantom.playbook_block()
def acquire_browser_history(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("acquire_browser_history() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    file_path_formatted_string = phantom.format(
        container=container,
        template="""C:\\Users\\<Username>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History,\nC:\\Users\\<Username>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<Profile>\\places.sqlite,\nMozilla Firefox: C:\\Users\\<Username>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<Profile>\\places.sqlite\n""",
        parameters=[
            ""
        ])

    parameters = []

    parameters.append({
        "file_path": file_path_formatted_string,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get file", parameters=parameters, name="acquire_browser_history", assets=["microsoft defender for endpoint (edr)"], callback=human_interaction_isolate_affected_machines)

    return


@phantom.playbook_block()
def human_interaction_isolate_affected_machines(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("human_interaction_isolate_affected_machines() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """Isolate Machines"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Isolate Machines?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="human_interaction_isolate_affected_machines", parameters=parameters, response_types=response_types, callback=isolate_affected_machines_human_interaction)

    return


@phantom.playbook_block()
def isolate_affected_machines_human_interaction(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("isolate_affected_machines_human_interaction() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["human_interaction_isolate_affected_machines:action_result.summary.responses.0", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        quarantine_device_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["human_interaction_isolate_affected_machines:action_result.summary.responses.0", "==", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        return

    return


@phantom.playbook_block()
def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("quarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    device_id_formatted_string = phantom.format(
        container=container,
        template="""testlap\n""",
        parameters=[
            ""
        ])

    parameters = []

    if device_id_formatted_string is not None:
        parameters.append({
            "type": "Full",
            "comment": "test",
            "timeout": 30,
            "device_id": device_id_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("quarantine device", parameters=parameters, name="quarantine_device_1", assets=["microsoft defender for endpoint (edr)"])

    return


@phantom.playbook_block()
def join_create_incident_ticket_via_jira(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_create_incident_ticket_via_jira() called")

    if phantom.completed(action_names=["block_url_on_proxy", "check_referer_url"]):
        # call connected block "create_incident_ticket_via_jira"
        create_incident_ticket_via_jira(container=container, handle=handle)

    return


@phantom.playbook_block()
def create_incident_ticket_via_jira(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_incident_ticket_via_jira() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "id": "test",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get ticket", parameters=parameters, name="create_incident_ticket_via_jira", assets=["jira"], callback=log_events_and_notify_soc)

    return


@phantom.playbook_block()
def join_check_referer_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_check_referer_url() called")

    if phantom.completed(action_names=["falcon_sandbox_check"]):
        # call connected block "check_referer_url"
        check_referer_url(container=container, handle=handle)

    return


@phantom.playbook_block()
def check_referer_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_referer_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "url": "referer",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="check_referer_url", assets=["virustotal "], callback=checking_useragent_traffic_contenttype_uri_scheme)

    return


@phantom.playbook_block()
def checking_useragent_traffic_contenttype_uri_scheme(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("checking_useragent_traffic_contenttype_uri_scheme() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.user_agent","artifact:*.cef.content_type","artifact:*.cef.bytes_received","artifact:*.cef.bytes_sent","artifact:*.cef.uri_scheme"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]
    container_artifact_cef_item_3 = [item[3] for item in container_artifact_data]
    container_artifact_cef_item_4 = [item[4] for item in container_artifact_data]

    checking_useragent_traffic_contenttype_uri_scheme__uri_scheme_check = None
    checking_useragent_traffic_contenttype_uri_scheme__content_type_check = None
    checking_useragent_traffic_contenttype_uri_scheme__traffic_patterns_check = None
    checking_useragent_traffic_contenttype_uri_scheme__user_agent_check = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="checking_useragent_traffic_contenttype_uri_scheme:uri_scheme_check", value=json.dumps(checking_useragent_traffic_contenttype_uri_scheme__uri_scheme_check))
    phantom.save_run_data(key="checking_useragent_traffic_contenttype_uri_scheme:content_type_check", value=json.dumps(checking_useragent_traffic_contenttype_uri_scheme__content_type_check))
    phantom.save_run_data(key="checking_useragent_traffic_contenttype_uri_scheme:traffic_patterns_check", value=json.dumps(checking_useragent_traffic_contenttype_uri_scheme__traffic_patterns_check))
    phantom.save_run_data(key="checking_useragent_traffic_contenttype_uri_scheme:user_agent_check", value=json.dumps(checking_useragent_traffic_contenttype_uri_scheme__user_agent_check))

    filter_1(container=container)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")



    return


@phantom.playbook_block()
def notify_soc_for_susicious_activity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("notify_soc_for_susicious_activity() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "to": "your_soc@your_company.com",
        "body": "test",
        "subject": "Suspicious Activity Detected",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="notify_soc_for_susicious_activity", assets=["smtp"])

    return


@phantom.playbook_block()
def log_events_and_notify_soc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("log_events_and_notify_soc() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    artifact_artifact_data = phantom.collect2(container=container, datapath=["artifact:*","artifact:*.id"])

    parameters = []

    # build parameters list for 'log_events_and_notify_soc' call
    for artifact_artifact_item in artifact_artifact_data:
        if artifact_artifact_item[0] is not None:
            parameters.append({
                "to": "your_soc@your_company.com",
                "body": artifact_artifact_item[0],
                "context": {'artifact_id': artifact_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="log_events_and_notify_soc", assets=["smtp"], callback=query_splunk_to_list_affected_users)

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