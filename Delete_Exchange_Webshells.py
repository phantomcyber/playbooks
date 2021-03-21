"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_More_Command' block
    Format_More_Command(container=container)

    return

def Delete_Webshell(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Delete_Webshell() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Delete_Webshell' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['Gather_Shell_Details:artifact:*.cef.destinationAddress', 'Gather_Shell_Details:artifact:*.id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='Format_Del_Command')

    parameters = []
    
    # build parameters list for 'Delete_Webshell' call
    for inputs_item_1 in inputs_data_1:
        parameters.append({
            'async': "",
            'parser': "",
            'command': formatted_data_1,
            'shell_id': "",
            'arguments': "",
            'command_id': "",
            'ip_hostname': inputs_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': inputs_item_1[1]},
        })

    phantom.act(action="run command", parameters=parameters, assets=['windowsrm'], name="Delete_Webshell")

    return

def Format_Del_Command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Del_Command() called')
    
    template = """del \"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.filePath",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Del_Command")

    Delete_Webshell(container=container)

    return

def Format_More_Command(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_More_Command() called')
    
    template = """more \"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.filePath",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_More_Command")

    Gather_Shell_Details(container=container)

    return

def Gather_Shell_Details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Gather_Shell_Details() called')

    # collect data for 'Gather_Shell_Details' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='Format_More_Command')

    parameters = []
    
    # build parameters list for 'Gather_Shell_Details' call
    for container_item in container_data:
        parameters.append({
            'async': "",
            'parser': "",
            'command': formatted_data_1,
            'shell_id': "",
            'arguments': "",
            'command_id': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="run command", parameters=parameters, assets=['windowsrm'], callback=Format_Del_Command, name="Gather_Shell_Details")

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