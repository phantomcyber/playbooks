"""
Create a ticket in another case management system to track this event. Use the title and description from the input, but also append a header and indicator summary table to share more information from the SOAR event.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'indicator_collect_1' block
    indicator_collect_1(container=container)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_ticket_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_ticket_title = phantom.collect2(container=container, datapath=["playbook_input:ticket_title"])
    format_ticket_description = phantom.get_format_data(name="format_ticket_description")

    parameters = []

    # build parameters list for 'create_ticket_1' call
    for playbook_input_ticket_title_item in playbook_input_ticket_title:
        parameters.append({
            "table": "incident",
            "description": format_ticket_description,
            "short_description": playbook_input_ticket_title_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="create_ticket_1", assets=["servicenow"])

    return


def indicator_collect_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_collect_1() called")

    id_value = container.get("id", None)
    playbook_input_artifact_ids_include = phantom.collect2(container=container, datapath=["playbook_input:artifact_ids_include"])
    playbook_input_indicator_types_include = phantom.collect2(container=container, datapath=["playbook_input:indicator_types_include"])
    playbook_input_indicator_types_exclude = phantom.collect2(container=container, datapath=["playbook_input:indicator_types_exclude"])
    playbook_input_indicator_tags_include = phantom.collect2(container=container, datapath=["playbook_input:indicator_tags_include"])
    playbook_input_indicator_tags_exclude = phantom.collect2(container=container, datapath=["playbook_input:indicator_tags_exclude"])

    playbook_input_artifact_ids_include_values = [item[0] for item in playbook_input_artifact_ids_include]
    playbook_input_indicator_types_include_values = [item[0] for item in playbook_input_indicator_types_include]
    playbook_input_indicator_types_exclude_values = [item[0] for item in playbook_input_indicator_types_exclude]
    playbook_input_indicator_tags_include_values = [item[0] for item in playbook_input_indicator_tags_include]
    playbook_input_indicator_tags_exclude_values = [item[0] for item in playbook_input_indicator_tags_exclude]

    parameters = []

    parameters.append({
        "container": id_value,
        "artifact_ids_include": playbook_input_artifact_ids_include_values,
        "indicator_types_include": playbook_input_indicator_types_include_values,
        "indicator_types_exclude": playbook_input_indicator_types_exclude_values,
        "indicator_tags_include": playbook_input_indicator_tags_include_values,
        "indicator_tags_exclude": playbook_input_indicator_tags_exclude_values,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters[0]["artifact_ids_include"] = ', '.join([item[0] for item in playbook_input_artifact_ids_include_values if item])
    parameters[0]["indicator_types_include"] = ', '.join([item[0] for item in playbook_input_indicator_types_include_values if item])
    parameters[0]["indicator_types_exclude"] = ', '.join([item[0] for item in playbook_input_indicator_types_exclude_values if item])
    parameters[0]["indicator_tags_include"] = ', '.join([item[0] for item in playbook_input_indicator_tags_include_values if item])
    parameters[0]["indicator_tags_exclude"] = ', '.join([item[0] for item in playbook_input_indicator_tags_exclude_values if item])

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_collect", parameters=parameters, name="indicator_collect_1", callback=format_ticket_description)

    return


def format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_ticket_description() called")

    template = """Tracking SOAR event: {0}\n\n{1}\n\nSummary Table of select indicators from event:\n\n%%\nindicator value: {2}\nindicator tags: {3}\nSOAR artifact ID: {4}\n\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "playbook_input:ticket_description",
        "indicator_collect_1:custom_function_result.data.all_indicators.*.cef_value",
        "indicator_collect_1:custom_function_result.data.all_indicators.*.tags",
        "indicator_collect_1:custom_function_result.data.all_indicators.*.artifact_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_description")

    create_ticket_1(container=container)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    create_ticket_1_result_data = phantom.collect2(container=container, datapath=["create_ticket_1:action_result.summary.created_ticket_id"])

    create_ticket_1_summary_created_ticket_id = [item[0] for item in create_ticket_1_result_data]

    output = {
        "ticket_id": create_ticket_1_summary_created_ticket_id,
    }

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

    phantom.save_playbook_output_data(output=output)

    return