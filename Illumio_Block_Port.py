"""
Block traffic to all Illumio managed workloads on a given port.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_global_ip_list' block
    get_global_ip_list(container=container)

    return

@phantom.playbook_block()
def port_block_settings(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("port_block_settings() called")

    ################################################################################
    # Prompts the user to choose whether or not to allowlist destinations that received 
    # traffic on the port to be blocked during a defined time range.
    # 
    # Additionally, the user chooses whether or not to update any managed workloads 
    # from "Visibility Only" to "Selective" enforcement after the enforcement boundary 
    # is created.
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Blocking port {0} {1}.\n\nPlease input whether to create an allowlist based on historical traffic (you will be prompted for a time range) and whether to automatically update any workloads from \"Visibility Only\" to \"Selective\" enforcement."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:port",
        "playbook_input:protocol"
    ]

    # responses
    response_types = [
        {
            "prompt": "Allowlist traffic to destinations based on historical traffic?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Update enforcement mode for all Visibility Only workloads?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="port_block_settings", parameters=parameters, response_types=response_types, callback=should_traffic_query_run)

    return


@phantom.playbook_block()
def should_traffic_query_run(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("should_traffic_query_run() called")

    ################################################################################
    # Checks if the user chose to run or skip the allowlist traffic query.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["port_block_settings:action_result.summary.responses.0", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        traffic_query_time_range(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_block_port(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def traffic_query_time_range(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("traffic_query_time_range() called")

    ################################################################################
    # Prompts the user for the start and end times for the range to query for the 
    # allowlist. Destinations receiving potentially blocked traffic on the blocked 
    # port:protocol during the given range will be bound to a virtual service and 
    # allowlisted through the enforcement boundary.
    # 
    # Valid date formats are MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Please enter the beginning and end times for the traffic query range. An allowlist will be created for any potentially blocked traffic on {0} {1} to destinations receiving traffic within the given range."""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:port",
        "playbook_input:protocol"
    ]

    # responses
    response_types = [
        {
            "prompt": "Start Time (Valid date format: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "End Time (Valid date format: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss) ",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="traffic_query_time_range", parameters=parameters, response_types=response_types, callback=allowlist_traffic_query)

    return


@phantom.playbook_block()
def allowlist_traffic_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("allowlist_traffic_query() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    policy_decisions_formatted_string = phantom.format(
        container=container,
        template="""potentially_blocked,unknown""",
        parameters=[])

    ################################################################################
    # Queries the Illumio PCE for traffic within the configured range.
    ################################################################################

    playbook_input_port = phantom.collect2(container=container, datapath=["playbook_input:port"])
    traffic_query_time_range_result_data = phantom.collect2(container=container, datapath=["traffic_query_time_range:action_result.summary.responses.1","traffic_query_time_range:action_result.summary.responses.0","traffic_query_time_range:action_result.parameter.context.artifact_id"], action_results=results)
    playbook_input_protocol = phantom.collect2(container=container, datapath=["playbook_input:protocol"])

    parameters = []

    # build parameters list for 'allowlist_traffic_query' call
    for playbook_input_port_item in playbook_input_port:
        for traffic_query_time_range_result_item in traffic_query_time_range_result_data:
            for playbook_input_protocol_item in playbook_input_protocol:
                if playbook_input_port_item[0] is not None and traffic_query_time_range_result_item[0] is not None and playbook_input_protocol_item[0] is not None and traffic_query_time_range_result_item[1] is not None and policy_decisions_formatted_string is not None:
                    parameters.append({
                        "port": playbook_input_port_item[0],
                        "end_time": traffic_query_time_range_result_item[0],
                        "protocol": playbook_input_protocol_item[0],
                        "start_time": traffic_query_time_range_result_item[1],
                        "policy_decisions": policy_decisions_formatted_string,
                        "context": {'artifact_id': traffic_query_time_range_result_item[2]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get traffic analysis", parameters=parameters, name="allowlist_traffic_query", assets=["dfdev1"], callback=are_query_results_empty)

    return


@phantom.playbook_block()
def get_global_ip_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_global_ip_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gets the Any (0.0.0.0/0 and ::/0) default IP list from the PCE for use later 
    # in the playbook.
    ################################################################################

    parameters = []

    parameters.append({
        "name": "Any (0.0.0.0/0 and ::/0)",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get ip lists", parameters=parameters, name="get_global_ip_list", assets=["dfdev1"], callback=port_block_settings)

    return


@phantom.playbook_block()
def are_query_results_empty(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("are_query_results_empty() called")

    ################################################################################
    # Checks if traffic query results are empty. If not, the allowlist will be created.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["No traffic found", "in", "allowlist_traffic_query:action_result.message"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_block_port(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    create_virtual_service(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def join_block_port(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_block_port() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_block_port_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_block_port_called", value="block_port")

    # call connected block "block_port"
    block_port(container=container, handle=handle)

    return


@phantom.playbook_block()
def block_port(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_port() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    name_formatted_string = phantom.format(
        container=container,
        template="""EB-Splunk-SOAR-{0}-{1}\n""",
        parameters=[
            "playbook_input:port",
            "playbook_input:protocol"
        ])
    providers_formatted_string = phantom.format(
        container=container,
        template="""ams""",
        parameters=[])

    ################################################################################
    # Creates an Enforcement Boundary on the Illumio PCE to block traffic on the given 
    # port and protocol to all Illumio workloads from all sources.
    ################################################################################

    playbook_input_port = phantom.collect2(container=container, datapath=["playbook_input:port"])
    playbook_input_protocol = phantom.collect2(container=container, datapath=["playbook_input:protocol"])
    get_global_ip_list_result_data = phantom.collect2(container=container, datapath=["get_global_ip_list:action_result.data.*.ip_lists.0.href","get_global_ip_list:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'block_port' call
    for playbook_input_port_item in playbook_input_port:
        for playbook_input_protocol_item in playbook_input_protocol:
            for get_global_ip_list_result_item in get_global_ip_list_result_data:
                if name_formatted_string is not None and playbook_input_port_item[0] is not None and playbook_input_protocol_item[0] is not None and get_global_ip_list_result_item[0] is not None and providers_formatted_string is not None:
                    parameters.append({
                        "name": name_formatted_string,
                        "port": playbook_input_port_item[0],
                        "protocol": playbook_input_protocol_item[0],
                        "consumers": get_global_ip_list_result_item[0],
                        "providers": providers_formatted_string,
                        "context": {'artifact_id': get_global_ip_list_result_item[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create enforcement boundary", parameters=parameters, name="block_port", assets=["dfdev1"], callback=enforcement_boundary_exists)

    return


@phantom.playbook_block()
def provision_enforcement_boundary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("provision_enforcement_boundary() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Provisions the Enforcement Boundary on the Illumio PCE to move it from Draft 
    # to Active state.
    ################################################################################

    block_port_result_data = phantom.collect2(container=container, datapath=["block_port:action_result.data.*.href","block_port:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'provision_enforcement_boundary' call
    for block_port_result_item in block_port_result_data:
        if block_port_result_item[0] is not None:
            parameters.append({
                "hrefs": block_port_result_item[0],
                "context": {'artifact_id': block_port_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("provision objects", parameters=parameters, name="provision_enforcement_boundary", assets=["dfdev1"], callback=join_should_update_enforcement)

    return


@phantom.playbook_block()
def join_should_update_enforcement(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_should_update_enforcement() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_should_update_enforcement_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_should_update_enforcement_called", value="should_update_enforcement")

    # call connected block "should_update_enforcement"
    should_update_enforcement(container=container, handle=handle)

    return


@phantom.playbook_block()
def should_update_enforcement(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("should_update_enforcement() called")

    ################################################################################
    # Checks if the user chose to update enforcement mode for workloads in "Visibility 
    # Only" mode.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["port_block_settings:action_result.summary.responses.1", "==", "Yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_visibility_only_workloads(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def get_visibility_only_workloads(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_visibility_only_workloads() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    enforcement_mode_formatted_string = phantom.format(
        container=container,
        template="""visibility_only""",
        parameters=[])

    ################################################################################
    # Gets all managed workloads in "Visibility Only" enforcement mode from the Illumio 
    # PCE.
    ################################################################################

    parameters = []

    parameters.append({
        "max_results": 150000,
        "enforcement_mode": enforcement_mode_formatted_string,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get workloads", parameters=parameters, name="get_visibility_only_workloads", assets=["dfdev1"], callback=check_workloads_to_update)

    return


@phantom.playbook_block()
def enforce_visibility_only_workloads(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("enforce_visibility_only_workloads() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    enforcement_mode_formatted_string = phantom.format(
        container=container,
        template="""selective""",
        parameters=[])

    ################################################################################
    # Updates all managed workloads in "Visibility Only" enforcement to "Selective" 
    # mode.
    ################################################################################

    get_visibility_only_workloads_result_data = phantom.collect2(container=container, datapath=["get_visibility_only_workloads:action_result.data.*.workloads.*.href","get_visibility_only_workloads:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'enforce_visibility_only_workloads' call
    for get_visibility_only_workloads_result_item in get_visibility_only_workloads_result_data:
        if get_visibility_only_workloads_result_item[0] is not None and enforcement_mode_formatted_string is not None:
            parameters.append({
                "workload_hrefs": get_visibility_only_workloads_result_item[0],
                "enforcement_mode": enforcement_mode_formatted_string,
                "context": {'artifact_id': get_visibility_only_workloads_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update enforcement mode", parameters=parameters, name="enforce_visibility_only_workloads", assets=["dfdev1"])

    return


@phantom.playbook_block()
def create_virtual_service(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_virtual_service() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    name_formatted_string = phantom.format(
        container=container,
        template="""VS-Splunk-SOAR-{0}-{1}\n""",
        parameters=[
            "playbook_input:port",
            "playbook_input:protocol"
        ])

    ################################################################################
    # Creates a Virtual Service on the Illumio PCE to bind all allowlisted workloads.
    ################################################################################

    playbook_input_port = phantom.collect2(container=container, datapath=["playbook_input:port"])
    playbook_input_protocol = phantom.collect2(container=container, datapath=["playbook_input:protocol"])

    parameters = []

    # build parameters list for 'create_virtual_service' call
    for playbook_input_port_item in playbook_input_port:
        for playbook_input_protocol_item in playbook_input_protocol:
            if name_formatted_string is not None and playbook_input_port_item[0] is not None and playbook_input_protocol_item[0] is not None:
                parameters.append({
                    "name": name_formatted_string,
                    "port": playbook_input_port_item[0],
                    "protocol": playbook_input_protocol_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create virtual service", parameters=parameters, name="create_virtual_service", assets=["dfdev1"], callback=virtual_service_exists)

    return


@phantom.playbook_block()
def provision_virtual_service(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("provision_virtual_service() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Provisions the Virtual Service on the Illumio PCE to move it from Draft to Active 
    # state. It must be provisioned before workloads can be bound to it.
    ################################################################################

    create_virtual_service_result_data = phantom.collect2(container=container, datapath=["create_virtual_service:action_result.data.*.href","create_virtual_service:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'provision_virtual_service' call
    for create_virtual_service_result_item in create_virtual_service_result_data:
        if create_virtual_service_result_item[0] is not None:
            parameters.append({
                "hrefs": create_virtual_service_result_item[0],
                "context": {'artifact_id': create_virtual_service_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("provision objects", parameters=parameters, name="provision_virtual_service", assets=["dfdev1"], callback=join_bind_allowlisted_workloads)

    return


@phantom.playbook_block()
def join_bind_allowlisted_workloads(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_bind_allowlisted_workloads() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_bind_allowlisted_workloads_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_bind_allowlisted_workloads_called", value="bind_allowlisted_workloads")

    # call connected block "bind_allowlisted_workloads"
    bind_allowlisted_workloads(container=container, handle=handle)

    return


@phantom.playbook_block()
def bind_allowlisted_workloads(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("bind_allowlisted_workloads() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Creates Service Bindings for all destination workloads found in the allowlist 
    # traffic query.
    ################################################################################

    allowlist_traffic_query_result_data = phantom.collect2(container=container, datapath=["allowlist_traffic_query:action_result.data.*.traffic_flows.*.dst.workload.href","allowlist_traffic_query:action_result.parameter.context.artifact_id"], action_results=results)
    create_virtual_service_result_data = phantom.collect2(container=container, datapath=["create_virtual_service:action_result.data.*.href","create_virtual_service:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'bind_allowlisted_workloads' call
    for allowlist_traffic_query_result_item in allowlist_traffic_query_result_data:
        for create_virtual_service_result_item in create_virtual_service_result_data:
            if allowlist_traffic_query_result_item[0] is not None and create_virtual_service_result_item[0] is not None:
                parameters.append({
                    "workload_hrefs": allowlist_traffic_query_result_item[0],
                    "virtual_service_href": create_virtual_service_result_item[0],
                    "context": {'artifact_id': create_virtual_service_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # If the virtual service already exists when the playbook is run, we'll skip
    # the intermediate provisioning step. Instead, update the create_virtual_service
    # HREF result to its active-state representation.
    active_href = parameters[0]["virtual_service_href"].replace("/draft/", "/active/")
    parameters[0]["virtual_service_href"] = active_href

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create service binding", parameters=parameters, name="bind_allowlisted_workloads", assets=["dfdev1"], callback=create_allowlist_rule_set)

    return


@phantom.playbook_block()
def create_allowlist_rule_set(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_allowlist_rule_set() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    name_formatted_string = phantom.format(
        container=container,
        template="""RS-Splunk-SOAR-{0}-{1}""",
        parameters=[
            "playbook_input:port",
            "playbook_input:protocol"
        ])

    ################################################################################
    # Creates a Rule Set on the Illumio PCE to bound the allowlist policy.
    ################################################################################

    playbook_input_port = phantom.collect2(container=container, datapath=["playbook_input:port"])
    playbook_input_protocol = phantom.collect2(container=container, datapath=["playbook_input:protocol"])

    parameters = []

    # build parameters list for 'create_allowlist_rule_set' call
    for playbook_input_port_item in playbook_input_port:
        for playbook_input_protocol_item in playbook_input_protocol:
            if name_formatted_string is not None:
                parameters.append({
                    "name": name_formatted_string,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ruleset", parameters=parameters, name="create_allowlist_rule_set", assets=["dfdev1"], callback=rule_set_exists)

    return


@phantom.playbook_block()
def create_allowlist_rule(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_allowlist_rule() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    resolve_consumers_as_formatted_string = phantom.format(
        container=container,
        template="""workloads""",
        parameters=[])
    resolve_providers_as_formatted_string = phantom.format(
        container=container,
        template="""virtual_services""",
        parameters=[])

    ################################################################################
    # Creates a rule for the allowlist policy on the Illumio PCE.
    ################################################################################

    get_global_ip_list_result_data = phantom.collect2(container=container, datapath=["get_global_ip_list:action_result.data.*.ip_lists.0.href","get_global_ip_list:action_result.parameter.context.artifact_id"], action_results=results)
    create_virtual_service_result_data = phantom.collect2(container=container, datapath=["create_virtual_service:action_result.data.*.href","create_virtual_service:action_result.parameter.context.artifact_id"], action_results=results)
    create_allowlist_rule_set_result_data = phantom.collect2(container=container, datapath=["create_allowlist_rule_set:action_result.data.*.href","create_allowlist_rule_set:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'create_allowlist_rule' call
    for get_global_ip_list_result_item in get_global_ip_list_result_data:
        for create_virtual_service_result_item in create_virtual_service_result_data:
            for create_allowlist_rule_set_result_item in create_allowlist_rule_set_result_data:
                if get_global_ip_list_result_item[0] is not None and create_virtual_service_result_item[0] is not None and create_allowlist_rule_set_result_item[0] is not None and resolve_consumers_as_formatted_string is not None and resolve_providers_as_formatted_string is not None:
                    parameters.append({
                        "consumers": get_global_ip_list_result_item[0],
                        "providers": create_virtual_service_result_item[0],
                        "ruleset_href": create_allowlist_rule_set_result_item[0],
                        "resolve_consumers_as": resolve_consumers_as_formatted_string,
                        "resolve_providers_as": resolve_providers_as_formatted_string,
                        "context": {'artifact_id': create_allowlist_rule_set_result_item[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create rule", parameters=parameters, name="create_allowlist_rule", assets=["dfdev1"], callback=provision_allowlist_rule_set)

    return


@phantom.playbook_block()
def provision_allowlist_rule_set(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("provision_allowlist_rule_set() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Provisions the allowlist Rule Set on the Illumio PCE to move it from Draft to 
    # Active state.
    ################################################################################

    create_allowlist_rule_set_result_data = phantom.collect2(container=container, datapath=["create_allowlist_rule_set:action_result.data.*.href","create_allowlist_rule_set:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'provision_allowlist_rule_set' call
    for create_allowlist_rule_set_result_item in create_allowlist_rule_set_result_data:
        if create_allowlist_rule_set_result_item[0] is not None:
            parameters.append({
                "hrefs": create_allowlist_rule_set_result_item[0],
                "context": {'artifact_id': create_allowlist_rule_set_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("provision objects", parameters=parameters, name="provision_allowlist_rule_set", assets=["dfdev1"], callback=join_block_port)

    return


@phantom.playbook_block()
def check_workloads_to_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_workloads_to_update() called")

    ################################################################################
    # Checks if the "Visibility Only" workloads query result is empty.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_visibility_only_workloads:action_result.data.*.workloads.*.agent.href", "!=", None]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        enforce_visibility_only_workloads(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def enforcement_boundary_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("enforcement_boundary_exists() called")

    ################################################################################
    # Check if the Enforcement Boundary already exists.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["Found existing enforcement boundary", "in", "block_port:action_result.message"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_should_update_enforcement(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    provision_enforcement_boundary(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def virtual_service_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("virtual_service_exists() called")

    ################################################################################
    # Check if the Virtual Service already exists.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["Found existing virtual service", "in", "create_virtual_service:action_result.message"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_bind_allowlisted_workloads(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    provision_virtual_service(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def rule_set_exists(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("rule_set_exists() called")

    ################################################################################
    # Check if the Rule Set already exists.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["Found existing ruleset", "in", "create_allowlist_rule_set:action_result.message"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_block_port(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    create_allowlist_rule(action=action, success=success, container=container, results=results, handle=handle)

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