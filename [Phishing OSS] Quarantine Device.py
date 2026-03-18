"""
This playbook identifies and quarantines devices that interacted with phishing indicators by searching activity logs and isolating affected endpoints.
"""


import phantom.rules as phantom # type: ignore
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def device_observable_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("device_observable_list() called")

    playbook_splunk_identifier_activity_analysis_1_output_observable = phantom.collect2(container=container, datapath=["playbook_splunk_identifier_activity_analysis_1:playbook_output:observable"])

    playbook_splunk_identifier_activity_analysis_1_output_observable_values = [item[0] for item in playbook_splunk_identifier_activity_analysis_1_output_observable]

    device_observable_list__device_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    observable_list=playbook_splunk_identifier_activity_analysis_1_output_observable_values
    #logic to extract list and make into an artifact with device list
    phantom.debug(observable_list)
    unique_asset_ids = set()
    for item in observable_list:
        if item and "identifier_activity" in item:
            for activity in item["identifier_activity"]:
                if "id" in activity:
                    unique_asset_ids.add(activity["id"])
    
    device_observable_list__device_list=sorted(unique_asset_ids)
    phantom.debug(device_observable_list__device_list)
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="device_observable_list__inputs:0:playbook_splunk_identifier_activity_analysis_1:playbook_output:observable", value=json.dumps(playbook_splunk_identifier_activity_analysis_1_output_observable_values))

    phantom.save_block_result(key="device_observable_list:device_list", value=json.dumps(device_observable_list__device_list))

    phantom.save_block_result(key="device_observable_list_called", value="True")

    quarantine_device_1(container=container)

    return


@phantom.playbook_block()
def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("quarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    connector_guid_formatted_string = phantom.format(
        container=container,
        template="""%%\n{0}\n%%""",
        parameters=[
            "device_observable_list:custom_function:device_list"
        ])

    device_observable_list__device_list = json.loads(_ if (_ := phantom.get_run_data(key="device_observable_list:device_list")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if connector_guid_formatted_string is not None:
        parameters.append({
            "connector_guid": connector_guid_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("quarantine device", parameters=parameters, name="quarantine_device_1", assets=["cisco_fireamp"])

    return


@phantom.playbook_block()
def parse_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("parse_indicators() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.cef"])

    filtered_artifact_0__cef = [item[0] for item in filtered_artifact_0_data_filter_1]

    parse_indicators__file_list = None
    parse_indicators__domain_list = None
    parse_indicators__ip_list = None
    parse_indicators__url_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    indicator_artifact=filtered_artifact_0__cef[0]
    indicators=indicator_artifact.get("indicators")
    phantom.debug(indicators)
    
    parse_indicators__file_list=indicators.get("hashes")
    phantom.debug(parse_indicators__file_list)
    parse_indicators__ip_list=indicators.get("ips")
    phantom.debug(parse_indicators__ip_list)
    parse_indicators__domain_list=indicators.get("domains")
    phantom.debug(parse_indicators__domain_list)
    parse_indicators__url_list=indicators.get("urls")
    phantom.debug(parse_indicators__url_list)
    #parse_indicators__email_list=indicators.get("emails")
    #phantom.debug(parse_indicators__email_list)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="parse_indicators__inputs:0:filtered-data:filter_1:condition_1:artifact:*.cef", value=json.dumps(filtered_artifact_0__cef))

    phantom.save_block_result(key="parse_indicators:file_list", value=json.dumps(parse_indicators__file_list))
    phantom.save_block_result(key="parse_indicators:domain_list", value=json.dumps(parse_indicators__domain_list))
    phantom.save_block_result(key="parse_indicators:ip_list", value=json.dumps(parse_indicators__ip_list))
    phantom.save_block_result(key="parse_indicators:url_list", value=json.dumps(parse_indicators__url_list))

    phantom.save_block_result(key="parse_indicators_called", value="True")

    playbook_splunk_identifier_activity_analysis_1(container=container)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "SAA Indicators"]
        ],
        conditions_dps=[
            ["artifact:*.name", "==", "SAA Indicators"]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        parse_indicators(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_splunk_identifier_activity_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_splunk_identifier_activity_analysis_1() called")

    parse_indicators__ip_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:ip_list")) != "" else "null")  # pylint: disable=used-before-assignment
    parse_indicators__url_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:url_list")) != "" else "null")  # pylint: disable=used-before-assignment
    parse_indicators__file_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:file_list")) != "" else "null")  # pylint: disable=used-before-assignment
    parse_indicators__domain_list = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:domain_list")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "ip": parse_indicators__ip_list,
        "url": parse_indicators__url_list,
        "file": parse_indicators__file_list,
        "domain": parse_indicators__domain_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/Splunk_Identifier_Activity_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/Splunk_Identifier_Activity_Analysis", container=container, name="playbook_splunk_identifier_activity_analysis_1", callback=device_observable_list, inputs=inputs)

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