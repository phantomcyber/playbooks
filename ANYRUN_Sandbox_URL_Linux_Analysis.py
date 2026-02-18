"""
This playbook is designed for automated URL analysis in the ANY.RUN Sandbox on a Linux virtual machine. It enriches artifacts through a ready-made workflow: submitting objects to the sandbox, retrieving verdicts, extracting IoCs, and generating detailed reports on malicious objects.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'detonate_url_linux' block
    detonate_url_linux(container=container)

    return

@phantom.playbook_block()
def detonate_url_linux(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("detonate_url_linux() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Submits URL for analysis in ANY.RUN Sandbox by vault_id(s)
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'detonate_url_linux' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "obj_url": playbook_input_url_item[0],
                "env_os": "ubuntu",
                "obj_ext_browser": "Google Chrome",
                "env_locale": "en-US",
                "opt_network_connect": True,
                "opt_network_fakenet": False,
                "opt_network_tor": False,
                "opt_network_geo": "fastest",
                "opt_network_mitm": False,
                "opt_network_residential_proxy": False,
                "opt_network_residential_proxy_geo": "fastest",
                "opt_privacy_type": "bylink",
                "opt_timeout": 120,
                "obj_ext_extension": True,
                "user_tags": "splunk-soar-analysis"
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url linux", parameters=parameters, name="detonate_url_linux", assets=["fkravtsov-test-2"], callback=get_analysis_verdict)

    return


@phantom.playbook_block()
def get_iocs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_iocs() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Retrieves the CSV Report with IoCs extracted from URL analysis by analysis_id
    ################################################################################

    get_analysis_verdict_result_data = phantom.collect2(container=container, datapath=["get_analysis_verdict:action_result.parameter.analysis_id","get_analysis_verdict:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_iocs' call
    for get_analysis_verdict_result_item in get_analysis_verdict_result_data:
        if get_analysis_verdict_result_item[0] is not None:
            parameters.append({
                "analysis_id": get_analysis_verdict_result_item[0],
                "context": {'artifact_id': get_analysis_verdict_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get iocs", parameters=parameters, name="get_iocs", assets=["fkravtsov-test-2"], callback=build_output_malicious)

    return


@phantom.playbook_block()
def get_analysis_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_analysis_verdict() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Retrieves the verdict based on the results of analyzing the URL by analysis_id
    ################################################################################

    detonate_url_linux_result_data = phantom.collect2(container=container, datapath=["detonate_url_linux:action_result.data.*.analysis_id","detonate_url_linux:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_analysis_verdict' call
    for detonate_url_linux_result_item in detonate_url_linux_result_data:
        if detonate_url_linux_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_url_linux_result_item[0],
                "context": {'artifact_id': detonate_url_linux_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get analysis verdict", parameters=parameters, name="get_analysis_verdict", assets=["fkravtsov-test-2"], callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_analysis_verdict:action_result.data.*.verdict", "==", "No threats detected"]
        ],
        conditions_dps=[
            ["get_analysis_verdict:action_result.data.*.verdict", "==", "No threats detected"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        build_output_safe(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    get_report(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def get_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Retrieves the JSON Report based on the results of analyzing the Malicious or 
    # Suspicious URL by analysis_id
    ################################################################################

    detonate_url_linux_result_data = phantom.collect2(container=container, datapath=["detonate_url_linux:action_result.data.*.analysis_id","detonate_url_linux:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_report' call
    for detonate_url_linux_result_item in detonate_url_linux_result_data:
        if detonate_url_linux_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_url_linux_result_item[0],
                "context": {'artifact_id': detonate_url_linux_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get report", parameters=parameters, name="get_report", assets=["fkravtsov-test-2"], callback=get_report_html)

    return


@phantom.playbook_block()
def get_report_html(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_report_html() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Retrieves the HTML Report based on the results of analyzing the Malicious or 
    # Suspicious URL by analysis_id
    ################################################################################

    detonate_url_linux_result_data = phantom.collect2(container=container, datapath=["detonate_url_linux:action_result.data.*.analysis_id","detonate_url_linux:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_report_html' call
    for detonate_url_linux_result_item in detonate_url_linux_result_data:
        if detonate_url_linux_result_item[0] is not None:
            parameters.append({
                "analysis_id": detonate_url_linux_result_item[0],
                "context": {'artifact_id': detonate_url_linux_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get report html", parameters=parameters, name="get_report_html", assets=["fkravtsov-test-2"], callback=get_iocs)

    return


@phantom.playbook_block()
def build_output_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_output_malicious() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    get_report_html_result_data = phantom.collect2(container=container, datapath=["get_report_html:action_result.data.*.analysis_url","get_report_html:action_result.data.*.tags"], action_results=results)
    get_analysis_verdict_result_data = phantom.collect2(container=container, datapath=["get_analysis_verdict:action_result.data.*.object_value","get_analysis_verdict:action_result.data.*.object_type","get_analysis_verdict:action_result.data.*.verdict"], action_results=results)

    get_report_html_result_item_0 = [item[0] for item in get_report_html_result_data]
    get_report_html_result_item_1 = [item[1] for item in get_report_html_result_data]
    get_analysis_verdict_result_item_0 = [item[0] for item in get_analysis_verdict_result_data]
    get_analysis_verdict_result_item_1 = [item[1] for item in get_analysis_verdict_result_data]
    get_analysis_verdict_result_item_2 = [item[2] for item in get_analysis_verdict_result_data]

    build_output_malicious__anyrun_analysis_results = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_output_malicious__inputs:0:get_report_html:action_result.data.*.analysis_url", value=json.dumps(get_report_html_result_item_0))
    phantom.save_block_result(key="build_output_malicious__inputs:1:get_analysis_verdict:action_result.data.*.object_value", value=json.dumps(get_analysis_verdict_result_item_0))
    phantom.save_block_result(key="build_output_malicious__inputs:2:get_analysis_verdict:action_result.data.*.object_type", value=json.dumps(get_analysis_verdict_result_item_1))
    phantom.save_block_result(key="build_output_malicious__inputs:3:get_analysis_verdict:action_result.data.*.verdict", value=json.dumps(get_analysis_verdict_result_item_2))
    phantom.save_block_result(key="build_output_malicious__inputs:4:get_report_html:action_result.data.*.tags", value=json.dumps(get_report_html_result_item_1))

    phantom.save_block_result(key="build_output_malicious:anyrun_analysis_results", value=json.dumps(build_output_malicious__anyrun_analysis_results))

    return


@phantom.playbook_block()
def build_output_safe(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_output_safe() called")

    ################################################################################
    # This block uses custom code to generate an observable dictionary to output into 
    # the observables data path.
    ################################################################################

    get_report_1_result_data = phantom.collect2(container=container, datapath=["get_report_1:action_result.data.*.analysis_url"], action_results=results)
    get_analysis_verdict_result_data = phantom.collect2(container=container, datapath=["get_analysis_verdict:action_result.data.*.object_value","get_analysis_verdict:action_result.data.*.object_type","get_analysis_verdict:action_result.data.*.verdict"], action_results=results)

    get_report_1_result_item_0 = [item[0] for item in get_report_1_result_data]
    get_analysis_verdict_result_item_0 = [item[0] for item in get_analysis_verdict_result_data]
    get_analysis_verdict_result_item_1 = [item[1] for item in get_analysis_verdict_result_data]
    get_analysis_verdict_result_item_2 = [item[2] for item in get_analysis_verdict_result_data]

    build_output_safe__anyrun_analysis_results = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_output_safe__inputs:0:get_report_1:action_result.data.*.analysis_url", value=json.dumps(get_report_1_result_item_0))
    phantom.save_block_result(key="build_output_safe__inputs:1:get_analysis_verdict:action_result.data.*.object_value", value=json.dumps(get_analysis_verdict_result_item_0))
    phantom.save_block_result(key="build_output_safe__inputs:2:get_analysis_verdict:action_result.data.*.object_type", value=json.dumps(get_analysis_verdict_result_item_1))
    phantom.save_block_result(key="build_output_safe__inputs:3:get_analysis_verdict:action_result.data.*.verdict", value=json.dumps(get_analysis_verdict_result_item_2))

    phantom.save_block_result(key="build_output_safe:anyrun_analysis_results", value=json.dumps(build_output_safe__anyrun_analysis_results))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "results": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    build_output__anyrun_analysis_results = json.loads(_ if (_ := phantom.get_run_data(
        key="build_output:anyrun_analysis_results")) != "" else "null")  # pylint: disable=used-before-assignment
    build_output_1__anyrun_analysis_results = json.loads(_ if (_ := phantom.get_run_data(
        key="build_output_1:anyrun_analysis_results")) != "" else "null")  # pylint: disable=used-before-assignment

    if build_output__anyrun_analysis_results:
        output["results"] = build_output__anyrun_analysis_results
    else:
        output["results"] = build_output_1__anyrun_analysis_results

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return