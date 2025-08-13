"""
This Playbook is designed to give you in depth insight not only into the affected Crowdstrike device, but also other devices in the Crowdstrike environment. \n\nFirst, it will hunt for the possible malicious File Hashes and IPs on other environment.  At the same time it delivers URL and File Reputation from your Crowdstrike environment on relatable artifacts.  \n\nLastly, via prompt you will be delivered with pertinent information relating to actions run above.  You will then be tasked to answer Yes/No on Network Isolation of device, Deny listing of files and file eviction from device completely. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_owner_is_set' block
    check_owner_is_set(container=container)

    return

@phantom.playbook_block()
def add_executable_denylisting_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_executable_denylisting_results() called")

    ################################################################################
    # Add a note on the event with the results (markdown format) of the Executable 
    # Denylisting input playbook run.
    ################################################################################

    perform_executable_denylisting_output_markdown_report = phantom.collect2(container=container, datapath=["perform_executable_denylisting:playbook_output:markdown_report"])

    perform_executable_denylisting_output_markdown_report_values = [item[0] for item in perform_executable_denylisting_output_markdown_report]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=perform_executable_denylisting_output_markdown_report_values, note_format="markdown", note_type="general", title="Executable Denylisting Results")

    return


@phantom.playbook_block()
def add_file_eviction_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_file_eviction_results() called")

    ################################################################################
    # Add a note on the event with the results (markdown format) of the File Eviction 
    # input playbook run.
    ################################################################################

    perform_file_eviction_output_markdown_report = phantom.collect2(container=container, datapath=["perform_file_eviction:playbook_output:markdown_report"])

    perform_file_eviction_output_markdown_report_values = [item[0] for item in perform_file_eviction_output_markdown_report]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=perform_file_eviction_output_markdown_report_values, note_format="markdown", note_type="general", title="File Eviction Results")

    return


@phantom.playbook_block()
def add_network_isolation_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_network_isolation_results() called")

    ################################################################################
    # Add a note on the event with the results (markdown format) of the Network Isolation 
    # input playbook run.
    ################################################################################

    perform_network_isolation_output_markdown_report = phantom.collect2(container=container, datapath=["perform_network_isolation:playbook_output:markdown_report"])

    perform_network_isolation_output_markdown_report_values = [item[0] for item in perform_network_isolation_output_markdown_report]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=perform_network_isolation_output_markdown_report_values, note_format="markdown", note_type="general", title="Network Isolation Results")

    return


@phantom.playbook_block()
def format_complete_file_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_complete_file_path() called")

    ################################################################################
    # Concatenates the filePath and fileName attributes together for the File Collection 
    # input playbook which needs it.
    ################################################################################

    template = """{0}\\{1}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.filePath",
        "artifact:*.cef.fileName"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_complete_file_path")

    perform_file_collection(container=container)

    return


@phantom.playbook_block()
def add_file_collection_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_file_collection_results() called")

    ################################################################################
    # Add a note on the event with the results (markdown format) of the File Collection 
    # input playbook run.
    ################################################################################

    perform_file_collection_output_markdown_report = phantom.collect2(container=container, datapath=["perform_file_collection:playbook_output:markdown_report"])

    perform_file_collection_output_markdown_report_values = [item[0] for item in perform_file_collection_output_markdown_report]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=perform_file_collection_output_markdown_report_values, note_format="markdown", note_type="general", title="File Collection Results")

    perform_file_eviction(container=container)

    return


@phantom.playbook_block()
def format_analyst_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_analyst_message() called")

    ################################################################################
    # Format the message containing the results of all the enrichment activities done 
    # so it can be presented to the analyst.
    ################################################################################

    template = """### {0}\n\n#### Detection Link\n[Open Alert in CrowdStrike]({1})\n\n#### Affected Host Details\n| Hostname | Domain | IP | External IP | Type | OS |\n| --- | --- | --- | --- | --- | --- |\n| {2} | {3} | {4} | {5} | {6} | {7} |\n\n{8}\n\n{9}\n\n{10}\n\n{11}\n\n{12}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "artifact:*.cef.falconHostLink",
        "artifact:*.cef.sourceHostName",
        "perform_ioc_enrichment:playbook_output:endpoint_observable.endpoint_artifacts.0.domain",
        "perform_ioc_enrichment:playbook_output:endpoint_observable.endpoint_artifacts.0.ip",
        "perform_ioc_enrichment:playbook_output:endpoint_observable.endpoint_artifacts.0.external_ip",
        "perform_ioc_enrichment:playbook_output:endpoint_observable.endpoint_artifacts.0.type",
        "perform_ioc_enrichment:playbook_output:endpoint_observable.endpoint_artifacts.0.operating_system.name",
        "perform_ioc_enrichment:playbook_output:file_reputation_results",
        "perform_ioc_enrichment:playbook_output:url_reputation_results",
        "perform_ioc_enrichment:playbook_output:hunt_ip_results",
        "perform_ioc_enrichment:playbook_output:hunt_domain_results",
        "perform_ioc_enrichment:playbook_output:hunt_file_results"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_analyst_message")

    prompt_analyst(container=container)

    return


@phantom.playbook_block()
def prompt_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_analyst() called")

    ################################################################################
    # Prompt the analyst with the enrichment information and ask for response actions 
    # that should be executed.
    ################################################################################

    # set approver and message variables for phantom.prompt call

    user = container.get('owner_name', None)
    role = None
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_analyst_message:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Block file hash?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Quarantine device?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Collect and delete file on the affected endpoint?",
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

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_analyst", parameters=parameters, response_types=response_types, callback=perform_applicable_response_actions)

    return


@phantom.playbook_block()
def check_owner_is_set(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_owner_is_set() called")

    ################################################################################
    # This playbook expects an analyst is assigned as the owner of the source event/alert. 
    #  If not set, abort with a message.
    ################################################################################

    owner_value = container.get("owner", None)

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            [owner_value, "!=", ""]
        ],
        conditions_dps=[
            ["container:owner", "!=", ""]
        ],
        name="check_owner_is_set:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    add_owner_missing_note(action=action, success=success, container=container, results=results, handle=handle)
    perform_ioc_enrichment(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_owner_missing_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_owner_missing_note() called")

    ################################################################################
    # Add a note to ensure users know the event on which this playbook is being run 
    # needs to have an owner assigned.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content="Please ensure an event owner is set before running this playbook.", note_format="markdown", note_type="general", title="Missing information")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def perform_applicable_response_actions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_applicable_response_actions() called")

    ################################################################################
    # Perform response actions based on the selections made by the analyst.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["prompt_analyst:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="perform_applicable_response_actions:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        perform_executable_denylisting(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.1", "==", "Yes"]
        ],
        conditions_dps=[
            ["prompt_analyst:action_result.summary.responses.1", "==", "Yes"]
        ],
        name="perform_applicable_response_actions:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        perform_network_isolation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.2", "==", "Yes"]
        ],
        conditions_dps=[
            ["prompt_analyst:action_result.summary.responses.2", "==", "Yes"]
        ],
        name="perform_applicable_response_actions:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        format_complete_file_path(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def perform_ioc_enrichment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_ioc_enrichment() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Crowdstrike_OAuth_API_Endpoint_IOC_Enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Crowdstrike_OAuth_API_Endpoint_IOC_Enrichment", container=container, name="perform_ioc_enrichment", callback=format_analyst_message)

    return


@phantom.playbook_block()
def perform_network_isolation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_network_isolation() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceHostName"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "device": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/CrowdStrike_OAuth_API_Network_Isolation", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/CrowdStrike_OAuth_API_Network_Isolation", container=container, name="perform_network_isolation", callback=add_network_isolation_results, inputs=inputs)

    return


@phantom.playbook_block()
def perform_executable_denylisting(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_executable_denylisting() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceHostName","artifact:*.cef.fileHashSha256"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    inputs = {
        "device": container_artifact_cef_item_0,
        "hash": container_artifact_cef_item_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/CrowdStrike_OAuth_API_Executable_Denylisting", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/CrowdStrike_OAuth_API_Executable_Denylisting", container=container, name="perform_executable_denylisting", callback=add_executable_denylisting_results, inputs=inputs)

    return


@phantom.playbook_block()
def perform_file_collection(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_file_collection() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceHostName"])
    format_complete_file_path = phantom.get_format_data(name="format_complete_file_path")

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "device": container_artifact_cef_item_0,
        "path": format_complete_file_path,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/CrowdStrike_OAuth_API_File_Collection", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/CrowdStrike_OAuth_API_File_Collection", container=container, name="perform_file_collection", callback=add_file_collection_results, inputs=inputs)

    return


@phantom.playbook_block()
def perform_file_eviction(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("perform_file_eviction() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceHostName"])
    format_complete_file_path = phantom.get_format_data(name="format_complete_file_path")

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "device": container_artifact_cef_item_0,
        "path": format_complete_file_path,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/CrowdStrike_OAuth_API_File_Eviction", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/CrowdStrike_OAuth_API_File_Eviction", container=container, name="perform_file_eviction", callback=add_file_eviction_results, inputs=inputs)

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