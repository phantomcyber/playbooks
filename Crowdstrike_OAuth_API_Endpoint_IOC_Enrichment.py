"""
This Playbook is designed to give you in depth insight not only into the affected Crowdstrike device, but also other devices in the Crowdstrike environment. \n\nFirst, it will hunt for the possible malicious File Hashes, URL/Domains and IPs on other environment.  At the same time it delivers URL and File Reputation from your Crowdstrike environment on relatable artifacts.  \n\nLastly, via prompt you will be delivered with pertinent information relating to actions run above.  You will then be tasked to answer Yes/No on Network Isolation of device, blocking the execution of malicious files and file eviction from the device completely. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'ioc_filter' block
    ioc_filter(container=container)

    return

@phantom.playbook_block()
def hunt_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hunt_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Hunt for a file IOCs on the network by querying CrowdStrike and collect the 
    # information in order to present it to the analyst to inform later response within 
    # the playbook.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'hunt_file' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "limit": 100,
                "count_only": False,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt file", parameters=parameters, name="hunt_file", assets=["crowdstrike_oauth_api"], callback=crowdstrike_oauth_api_get_device_info_file)

    return


@phantom.playbook_block()
def ioc_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ioc_filter() called")

    ################################################################################
    # Filters the different type of IOCs present in the event sent to the playbook.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHash", "!=", ""]
        ],
        name="ioc_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha256", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashSha256", "!=", ""]
        ],
        name="ioc_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        file_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="ioc_filter:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        url_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids and results for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.dst", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.dst", "!=", ""]
        ],
        name="ioc_filter:condition_4",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        hunt_ip(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids and results for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceHostName", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.sourceHostName", "!=", ""]
        ],
        name="ioc_filter:condition_5",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        crowdstrike_oauth_api_endpoint_analysis(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return


@phantom.playbook_block()
def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Look up the reputation of file IOCs from CrowdStrike and collect the information 
    # in order to present it to the analyst to inform later response within the playbook.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHashSha256","artifact:*.cef.vaultId","artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "limit": 50,
            "sha256": container_artifact_item[0],
            "vault_id": container_artifact_item[1],
            "context": {'artifact_id': container_artifact_item[2]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation", assets=["crowdstrike_oauth_api"], callback=format_file_reputation_results)

    return


@phantom.playbook_block()
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Queries CrowdStrike for information about the reputation of the URL IOCs.   
    # This is collected to better inform the analyst for later response in the playbook.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL","artifact:*.id"])

    parameters = []

    # build parameters list for 'url_reputation' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "limit": 50,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation", assets=["crowdstrike_oauth_api"], callback=url_parse)

    return


@phantom.playbook_block()
def hunt_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hunt_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Get a list of device IDs on which the IP address IOC was matched on the network 
    # by querying CrowdStrike and collect the information in order to present it to 
    # the analyst to inform later response within the playbook.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.dst","artifact:*.id"])

    parameters = []

    # build parameters list for 'hunt_ip' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "limit": 100,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt ip", parameters=parameters, name="hunt_ip", assets=["crowdstrike_oauth_api"], callback=crowdstrike_oauth_api_get_device_info_ip)

    return


@phantom.playbook_block()
def crowdstrike_oauth_api_endpoint_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_oauth_api_endpoint_analysis() called")

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

    # call playbook "local/CrowdStrike_OAuth_API_Endpoint_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Endpoint_Analysis", container=container, name="crowdstrike_oauth_api_endpoint_analysis", callback=crowdstrike_oauth_api_endpoint_analysis_callback, inputs=inputs)

    return


@phantom.playbook_block()
def crowdstrike_oauth_api_endpoint_analysis_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_oauth_api_endpoint_analysis_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def crowdstrike_oauth_api_get_device_info_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_oauth_api_get_device_info_file() called")

    hunt_file_result_data = phantom.collect2(container=container, datapath=["hunt_file:action_result.data.*.device_id"], action_results=results)

    hunt_file_result_item_0 = [item[0] for item in hunt_file_result_data]

    inputs = {
        "device": hunt_file_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CrowdStrike_OAuth_API_Get_Device_Info", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Get_Device_Info", container=container, name="crowdstrike_oauth_api_get_device_info_file", callback=format_hunt_file_results, inputs=inputs)

    return


@phantom.playbook_block()
def crowdstrike_oauth_api_get_device_info_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_oauth_api_get_device_info_ip() called")

    hunt_ip_result_data = phantom.collect2(container=container, datapath=["hunt_ip:action_result.data.*.device_id"], action_results=results)

    hunt_ip_result_item_0 = [item[0] for item in hunt_ip_result_data]

    inputs = {
        "device": hunt_ip_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CrowdStrike_OAuth_API_Get_Device_Info", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Get_Device_Info", container=container, name="crowdstrike_oauth_api_get_device_info_ip", callback=format_hunt_ip_results, inputs=inputs)

    return


@phantom.playbook_block()
def hunt_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hunt_domain() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Hunt for the domain part of the requestURL to see if it was seen on other endpoints 
    # in the environment.  That context will then be presented to the analyst if relevant 
    # to guide response.
    ################################################################################

    url_parse__result = phantom.collect2(container=container, datapath=["url_parse:custom_function_result.data.netloc"])

    parameters = []

    # build parameters list for 'hunt_domain' call
    for url_parse__result_item in url_parse__result:
        if url_parse__result_item[0] is not None:
            parameters.append({
                "limit": 100,
                "domain": url_parse__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt domain", parameters=parameters, name="hunt_domain", assets=["crowdstrike_oauth_api"], callback=format_url_reputation_results)

    return


@phantom.playbook_block()
def url_parse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_parse() called")

    ################################################################################
    # Parse the requestURL attribute into its constituent parts, mostly to get the 
    # domain for later blocks.
    ################################################################################

    filtered_artifact_0_data_ioc_filter = phantom.collect2(container=container, datapath=["filtered-data:ioc_filter:condition_3:artifact:*.cef.requestURL","filtered-data:ioc_filter:condition_3:artifact:*.id"])

    parameters = []

    # build parameters list for 'url_parse' call
    for filtered_artifact_0_item_ioc_filter in filtered_artifact_0_data_ioc_filter:
        parameters.append({
            "input_url": filtered_artifact_0_item_ioc_filter[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/url_parse", parameters=parameters, name="url_parse", callback=hunt_domain)

    return


@phantom.playbook_block()
def format_file_reputation_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_file_reputation_results() called")

    ################################################################################
    # Format the results of the previous action block in Markdown format for later 
    # presentation.
    ################################################################################

    template = """#### File Reputation Results\n| File | Hash (SHA256) | Verdict | Total Reports\n| --- | --- | --- | --- |\n| {0} | {1} | {2} | {3} |"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ioc_filter:condition_2:artifact:*.cef.fileName",
        "file_reputation:action_result.parameter.sha256",
        "file_reputation:action_result.summary.verdict",
        "file_reputation:action_result.summary.total_reports"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_reputation_results")

    return


@phantom.playbook_block()
def format_hunt_file_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_hunt_file_results() called")

    ################################################################################
    # Format the results of the previous action block in Markdown format for later 
    # presentation.
    ################################################################################

    template = """#### Hunt File Results\n| File | Hash | Seen on |               \n| --- | --- | --- |\n| {0} | {1} | {2} |\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:ioc_filter:condition_1:artifact:*.cef.fileName",
        "hunt_file:action_result.parameter.hash",
        "crowdstrike_oauth_api_get_device_info_file:playbook_output:hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hunt_file_results")

    return


@phantom.playbook_block()
def format_hunt_ip_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_hunt_ip_results() called")

    ################################################################################
    # Format the results of the previous action block in Markdown format for later 
    # presentation.
    ################################################################################

    template = """#### Hunt IP Results\n| IP | Seen on |                  \n| --- | --- |                     \n| {0} | {1} |"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_ip:action_result.parameter.ip",
        "crowdstrike_oauth_api_get_device_info_ip:playbook_output:hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hunt_ip_results")

    return


@phantom.playbook_block()
def format_url_reputation_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_url_reputation_results() called")

    ################################################################################
    # Format the results of the previous action block in Markdown format for later 
    # presentation.
    ################################################################################

    template = """#### URL Reputation Results\n| URL | Verdict | Threat Score |\n| --- | --- | --- |     \n| {0} | {1} | {2} |\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation:action_result.parameter.url",
        "url_reputation:action_result.summary.verdict",
        "url_reputation:action_result.data.*.sandbox.*.threat_score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_reputation_results")

    crowdstrike_oauth_api_get_device_info_domain(container=container)

    return


@phantom.playbook_block()
def format_hunt_domain_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_hunt_domain_results() called")

    ################################################################################
    # Format the results of the previous action block in Markdown format for later 
    # presentation.
    ################################################################################

    template = """#### Hunt Domain Results\n| Domain | Seen on |                  \n| --- | --- |               \n| {0} | {1} |"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_domain:action_result.parameter.domain",
        "crowdstrike_oauth_api_get_device_info_domain:playbook_output:hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_hunt_domain_results")

    return


@phantom.playbook_block()
def crowdstrike_oauth_api_get_device_info_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("crowdstrike_oauth_api_get_device_info_domain() called")

    hunt_domain_result_data = phantom.collect2(container=container, datapath=["hunt_domain:action_result.data.*.device_id"], action_results=results)

    hunt_domain_result_item_0 = [item[0] for item in hunt_domain_result_data]

    inputs = {
        "device": hunt_domain_result_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/CrowdStrike_OAuth_API_Get_Device_Info", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/CrowdStrike_OAuth_API_Get_Device_Info", container=container, name="crowdstrike_oauth_api_get_device_info_domain", callback=format_hunt_domain_results, inputs=inputs)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    crowdstrike_oauth_api_endpoint_analysis_output_service_observable = phantom.collect2(container=container, datapath=["crowdstrike_oauth_api_endpoint_analysis:playbook_output:service_observable"])
    crowdstrike_oauth_api_endpoint_analysis_output_endpoint_observable = phantom.collect2(container=container, datapath=["crowdstrike_oauth_api_endpoint_analysis:playbook_output:endpoint_observable"])
    crowdstrike_oauth_api_endpoint_analysis_output_network_observable = phantom.collect2(container=container, datapath=["crowdstrike_oauth_api_endpoint_analysis:playbook_output:network_observable"])
    crowdstrike_oauth_api_endpoint_analysis_output_process_observable = phantom.collect2(container=container, datapath=["crowdstrike_oauth_api_endpoint_analysis:playbook_output:process_observable"])
    format_hunt_ip_results = phantom.get_format_data(name="format_hunt_ip_results")
    format_hunt_domain_results = phantom.get_format_data(name="format_hunt_domain_results")
    format_hunt_file_results = phantom.get_format_data(name="format_hunt_file_results")
    format_file_reputation_results = phantom.get_format_data(name="format_file_reputation_results")
    format_url_reputation_results = phantom.get_format_data(name="format_url_reputation_results")

    crowdstrike_oauth_api_endpoint_analysis_output_service_observable_values = [item[0] for item in crowdstrike_oauth_api_endpoint_analysis_output_service_observable]
    crowdstrike_oauth_api_endpoint_analysis_output_endpoint_observable_values = [item[0] for item in crowdstrike_oauth_api_endpoint_analysis_output_endpoint_observable]
    crowdstrike_oauth_api_endpoint_analysis_output_network_observable_values = [item[0] for item in crowdstrike_oauth_api_endpoint_analysis_output_network_observable]
    crowdstrike_oauth_api_endpoint_analysis_output_process_observable_values = [item[0] for item in crowdstrike_oauth_api_endpoint_analysis_output_process_observable]

    output = {
        "hunt_ip_results": format_hunt_ip_results,
        "hunt_domain_results": format_hunt_domain_results,
        "hunt_file_results": format_hunt_file_results,
        "file_reputation_results": format_file_reputation_results,
        "url_reputation_results": format_url_reputation_results,
        "services_observable": crowdstrike_oauth_api_endpoint_analysis_output_service_observable_values,
        "endpoint_observable": crowdstrike_oauth_api_endpoint_analysis_output_endpoint_observable_values,
        "network_observable": crowdstrike_oauth_api_endpoint_analysis_output_network_observable_values,
        "process_observable": crowdstrike_oauth_api_endpoint_analysis_output_process_observable_values,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return