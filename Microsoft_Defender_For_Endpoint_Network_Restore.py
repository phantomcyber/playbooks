"""
Accepts a uid (device_id or hostname) as input and quarantines the device in MS Defender for Endpoint. We then generate an observable report. The report can be customized based on user preference.\n\nRef:\nhttps://d3fend.mitre.org/technique/d3f:RestoreNetworkAccess/
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def unquarantine_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("unquarantine_device() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Unquarantines device in MS Defender for Endpoint given a uid (device_id or hostname).
    ################################################################################

    filtered_input_0_uid = phantom.collect2(container=container, datapath=["filtered-data:input_filter:condition_1:playbook_input:uid"])

    parameters = []

    # build parameters list for 'unquarantine_device' call
    for filtered_input_0_uid_item in filtered_input_0_uid:
        if filtered_input_0_uid_item[0] is not None:
            parameters.append({
                "comment": "Device removed from isolation via Splunk SOAR.",
                "timeout": 30,
                "device_id": filtered_input_0_uid_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("unquarantine device", parameters=parameters, name="unquarantine_device", assets=["defender-atp"], callback=unquarantine_device_filter)

    return


@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    ################################################################################
    # Determines if the provided inputs are present in the dataset.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:uid", "!=", ""]
        ],
        name="input_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        unquarantine_device(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def unquarantine_device_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("unquarantine_device_filter() called")

    ################################################################################
    # Filters successful unquarantine actions
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["unquarantine_device:action_result.status", "==", "success"]
        ],
        name="unquarantine_device_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_report_device(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def host_observables(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_observables() called")

    ################################################################################
    # Format a normalized output for each host
    ################################################################################

    filtered_result_0_data_unquarantine_device_filter = phantom.collect2(container=container, datapath=["filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.parameter.device_id","filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.data.*.computerDnsName"])
    unquarantine_device_result_data = phantom.collect2(container=container, datapath=["unquarantine_device:action_result.data.*.type"], action_results=results)

    filtered_result_0_parameter_device_id = [item[0] for item in filtered_result_0_data_unquarantine_device_filter]
    filtered_result_0_data___computerdnsname = [item[1] for item in filtered_result_0_data_unquarantine_device_filter]
    unquarantine_device_result_item_0 = [item[0] for item in unquarantine_device_result_data]

    host_observables__observable_array = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    code_1__observable_array = []
    
    for device_id, dns, isolationtype in zip(filtered_result_0_parameter_device_id, filtered_result_0_data___computerdnsname, unquarantine_device_result_item_0):
        # Initialize the observable dictionary
        observable = {
            "source": "Microsoft Defender for Endpoint",
            "type": "defender atp device id",
            "value": device_id,
            "attributes": {
                "computer_dns_name": dns,
                "isolation_type": isolationtype
            },
            "status": "active",
            "message": "Device removed from isolation successfully"
        }

        # Add the observable to the array
        code_1__observable_array.append(observable)
    
    # Debug output for verification
    phantom.debug(code_1__observable_array)
        
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="host_observables:observable_array", value=json.dumps(host_observables__observable_array))

    return


@phantom.playbook_block()
def format_report_device(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_report_device() called")

    ################################################################################
    # Format a summary table with the information gathered from the playbook.
    ################################################################################

    template = """Devices were removed from isolation via Splunk SOAR. The table below summarizes the information gathered.\n\n| Device ID | DNS Name | Isolation Type | Unquarantine Status |\n| --- | --- | --- | --- |\n%%\n| {0} | {1} | {2} | {3} |\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.data.*.machineId",
        "filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.data.*.computerDnsName",
        "filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.data.*.type",
        "filtered-data:unquarantine_device_filter:condition_1:unquarantine_device:action_result.status"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_report_device")

    host_observables(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_report_device = phantom.get_format_data(name="format_report_device")
    host_observables__observable_array = json.loads(_ if (_ := phantom.get_run_data(key="host_observables:observable_array")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "observable": host_observables__observable_array,
        "markdown_report": format_report_device,
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