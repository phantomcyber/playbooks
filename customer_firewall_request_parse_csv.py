"""
This playbook parses a .csv file with a list of firewall changes. The .csv file must contain an "action" column (with values equal to either "block_ip" or "unblock_ip") and either a "sourceAddress" column or a "destinationAddress" column. Once the .csv file is parsed this playbook will create one new artifact per row. The artifacts will have the label "customer_request" which can then be used in a subsequent playbook to take appropriate block or unblock actions.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

"""
The .csv file must be in the Vault and there must be an artifact with the cef.vaultId field.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.vaultId", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        customer_firewall_request_parse_csv(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Use custom code and the "csv" library to parse each row of the .csv file and create an artifact for each valid row, then call another playbook to handle the created artifact. 
"""
def customer_firewall_request_parse_csv(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_customer_firewall_request_parse_csv() called')

    # ----- start of added code -----
    import csv
    # get container id
    container_id = container.get('id', None)

    # use the container id to get information about any files in the vault
    vault_info = phantom.vault_info(container_id=container_id)

    # filter info returned to find the path where the file is stored in the vault
    file_path = vault_info[2][0]["path"]
    phantom.debug('vault file path: {}'.format(file_path))

    # read the .csv file, file and add artifacts with the label "customer_request" to container
    raw_data = {}
    reader = None
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for cef_data in reader:
                cef_data_keys = list(cef_data.keys())
                if 'action' in cef_data_keys and ('sourceAddress' in cef_data_keys or 'destinationAddress' in cef_data_keys):
                    phantom.debug('adding artifact: {}'.format(cef_data))
                    success, message, artifact_id = phantom.add_artifact(container=container,
                                                                         raw_data=raw_data,
                                                                         cef_data=cef_data,
                                                                         label='customer_request',
                                                                         name='Parsed CSV Artifact',
                                                                         severity='high',
                                                                         identifier=None,
                                                                         artifact_type='network')
                    if not success:
                        phantom.error("Adding Artifact failed: {}".format(message))
    except Exception as e:
        phantom.error("Exception Occurred: {}".format(e.args[1]))
        return
    # ----- end of added code -----

    # call playbook "local/customer_firewall_request_parse_csv", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/customer_firewall_request_parse_csv", container)

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