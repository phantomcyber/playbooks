"""
Moves the status to open and then launches the Dynamic playbooks for Reputation Analysis, Attribute Lookup, and Related Tickets.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_mission_control_identifier_reputation_analysis_1' block
    playbook_mission_control_identifier_reputation_analysis_1(container=container)

    return

@phantom.playbook_block()
def playbook_mission_control_identifier_reputation_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_mission_control_identifier_reputation_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Mission_Control_Identifier_Reputation_Analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Mission_Control_Identifier_Reputation_Analysis", container=container)

    playbook_mission_control_attribute_lookup_1(container=container)

    return


@phantom.playbook_block()
def playbook_mission_control_attribute_lookup_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_mission_control_attribute_lookup_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Mission_Control_Attribute_Lookup", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Mission_Control_Attribute_Lookup", container=container)

    playbook_mission_control_related_tickets_search_1(container=container)

    return


@phantom.playbook_block()
def playbook_mission_control_related_tickets_search_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_mission_control_related_tickets_search_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Mission_Control_Related_Tickets_Search", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Mission_Control_Related_Tickets_Search", container=container)

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