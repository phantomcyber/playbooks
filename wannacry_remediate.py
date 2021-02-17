"""
Execute remediation actions against endpoints associated with events that successfully match against the wannacry IOCs (file, domain, and IP indicators) by reverting VMs, reimaging endpoints or doing simple blocking actions
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

def add_endpoint_to_remediated_list(container):
        # collect data for 'add_to_remediated_list_1' call
    infected_endpoints = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    
    phantom_url = phantom.get_base_url()
    container_url = "{}/mission/{}".format(phantom_url, container['id'])
    
    for infected_endpoint in infected_endpoints:
        if infected_endpoint[0]:
            phantom.datastore_add('wannacry_remediated_endpoints', [ infected_endpoint[0], 'yes',  container_url ] )
            
    return

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')

    domains = phantom.datastore_get('wannacry_domains')
    if len(domains) == 0:
        phantom.datastore_set('wannacry_domains',
                              [ 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com',
                               'Rphjmrpwmfv6v2e.onion',
                               'Gx7ekbenv2riucmf.onion',
                               '57g7spgrzlojinas.onion',
                               'xxlvbrloxvriy2c5.onion',
                               '76jdd2ir2embyv47.onion',
                               'cwwnhwhlz52maqm7.onion',
                              ] )

    hashes = phantom.datastore_get('wannacry_hashes')
    if len(hashes) == 0:
        phantom.datastore_set('wannacry_hashes', 
                              [ 'dff26a9a44baa3ce109b8df41ae0a301d9e4a28ad7bd7721bbb7ccd137bfd696',
                               '201f42080e1c989774d05d5b127a8cd4b4781f1956b78df7c01112436c89b2c9',
                               'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
                               'c365ddaa345cfcaff3d629505572a484cff5221933d68e4a52130b8bb7badaf9',
                               '09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa',
                               'b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25',
                               'aae9536875784fe6e55357900519f97fee0a56d6780860779a36f06765243d56',
                               '21ed253b796f63b9e95b4e426a82303dfac5bf8062bfe669995bde2208b360fd',
                               '2372862afaa8e8720bc46f93cb27a9b12646a7cbc952cc732b8f5df7aebb2450',
                               '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
                               'f8812f1deb8001f3b7672b6fc85640ecb123bc2304b563728e6235ccbe782d85',
                               '4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79',
                               '4b76e54de0243274f97430b26624c44694fbde3289ed81a160e0754ab9f56f32',
                               '9cc32c94ce7dc6e48f86704625b6cdc0fda0d2cd7ad769e4d0bb1776903e5a13',
                               '78e3f87f31688355c0f398317b2d87d803bd87ee3656c5a7c80f0561ec8606df',
                               'be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844',
                               '5d26835be2cf4f08f2beeff301c06d05035d0a9ec3afacc71dff22813595c0b9',
                               '76a3666ce9119295104bb69ee7af3f2845d23f40ba48ace7987f79b06312bbdf',
                               'fc626fe1e0f4d77b34851a8c60cdd11172472da3b9325bfe288ac8342f6c710a',
                               'eeb9cd6a1c4b3949b2ff3134a77d6736b35977f951b9c7c911483b5caeb1c1fb',
                               '043e0d0d8b8cda56851f5b853f244f677bd1fd50f869075ef7ba1110771f70c2',
                               '57c12d8573d2f3883a8a0ba14e3eec02ac1c61dee6b675b6c0d16e221c3777f4',
                               'ca29de1dc8817868c93e54b09f557fe14e40083c0955294df5bd91f52ba469c8',
                               'f7c7b5e4b051ea5bd0017803f40af13bed224c4b0fd60b890b6784df5bd63494',
                               '3e6de9e2baacf930949647c399818e7a2caea2626df6a468407854aaa515eed9',
                               '9b60c622546dc45cca64df935b71c26dcf4886d6fa811944dbc4e23db9335640',
                               '5ad4efd90dcde01d26cc6f32f7ce3ce0b4d4951d4b94a19aa097341aff2acaec',
                               '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
                               '12d67c587e114d8dde56324741a8f04fb50cc3160653769b8015bc5aec64d20b',
                               '85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186',
                               '3f3a9dde96ec4107f67b0559b4e95f5f1bca1ec6cb204bfe5fea0230845e8301',
                               'aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c',
                              ] )

    file_names = phantom.datastore_get('wannacry_file_names')
    if len(file_names) == 0:
        phantom.datastore_set('wannacry_file_names', 
                              [ '@Please_Read_Me@.txt',
                               '@WanaDecryptor@.exe',
                               '@WanaDecryptor@.exe.lnk',
                               'Please Read Me!.txt',
                               'tasksche.exe',
                               'qeriuwjhrf',
                               '131181494299235.bat',
                               '176641494574290.bat',
                               '217201494590800.bat',
                               '!WannaDecryptor!.exe.lnk',
                               '00000000.pky',
                               '00000000.eky',
                               '00000000.res',
                               'taskdl.exe',
                              ] )

    ip_addrs = phantom.datastore_get('wannacry_ip_addrs')
    if len(ip_addrs) == 0:
        phantom.datastore_set('wannacry_ip_addrs', 
                              [ '197.231.221.221',
                               '128.31.0.39',
                               '149.202.160.69',
                               '46.101.166.19',
                               '91.121.65.179',
                               '2.3.69.209',
                               '146.0.32.144',
                               '50.7.161.218',
                               '217.79.179.177',
                               '213.61.66.116',
                               '212.47.232.237',
                               '81.30.158.223',
                               '79.172.193.32',
                               '38.229.72.16',
                              ] )

    # call 'decision_1' block
    decision_8(container=container)

    return

def block_hash_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_3' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_hash_3' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                'comment': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=filter_9, name="block_hash_3")

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fileHash", "in", "custom_list:wannacry_file_hashes"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_3() called')
    
    # set user and message variables for phantom.prompt call
    user = "Automation Engineer"
    message = """The infected endpoint info is:
DNS Name: 
{0}
Computer Name: 
{1}
OS info: 
{2}

Do you want to 
1. Contain the threat  by terminating the process and blocking the hash?
2. Or do you want to reimage the endpoint ?"""

    # parameter list for template variable replacement
    parameters = [
        "get_system_info_1:action_result.data.*.computer_dns_name",
        "get_system_info_1:action_result.data.*.computer_name",
        "get_system_info_1:action_result.data.*.os_environment_display_string",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "1",
                    "2",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_3", parameters=parameters, response_types=response_types, callback=decision_6)

    return

"""
Check the prompt response.
"""
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_3:action_result.summary.responses.0", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        list_processes_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_3:action_result.summary.responses.0", "==", 2],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        deactivate_partition_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def reboot_system_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reboot_system_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reboot_system_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reboot_system_1' call
    for container_item in container_data:
        parameters.append({
            'ph': "",
            'message': "",
            'wait_time': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="reboot system", parameters=parameters, assets=['domainctrl1'], name="reboot_system_1", parent_action=action)

    return

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fileHash", "in", "custom_list:wannacry_file_hashes"],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def terminate_malicious_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('terminate_malicious_process() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_malicious_process' call
    results_data_1 = phantom.collect2(container=container, datapath=['list_processes_3:action_result.parameter.ip_hostname', 'list_processes_3:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_6:condition_1:list_processes_3:action_result.data.*.pid", "filtered-data:filter_6:condition_1:list_processes_3:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'terminate_malicious_process' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if filtered_results_item_1[0]:
                parameters.append({
                    'pid': filtered_results_item_1[0],
                    'sensor_id': "",
                    'ip_hostname': results_item_1[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': filtered_results_item_1[1]},
                })

    phantom.act(action="terminate process", parameters=parameters, assets=['carbonblack'], callback=filter_7, name="terminate_malicious_process")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_processes_2:action_result.data.*.name", "in", "custom_list:wannacry_file_names"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        terminate_process_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def terminate_process_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('terminate_process_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_4' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_vm_info:action_result.data.*.ip', 'get_vm_info:action_result.parameter.context.artifact_id'], action_results=results)
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:list_processes_2:action_result.data.*.pid", "filtered-data:filter_4:condition_1:list_processes_2:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'terminate_process_4' call
    for results_item_1 in results_data_1:
        for filtered_results_item_1 in filtered_results_data_1:
            if filtered_results_item_1[0]:
                parameters.append({
                    'pid': filtered_results_item_1[0],
                    'sensor_id': "",
                    'ip_hostname': results_item_1[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': filtered_results_item_1[1]},
                })

    phantom.act(action="terminate process", parameters=parameters, assets=['carbonblack'], callback=filter_5, name="terminate_process_4")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "==", "custom_list:wannacry_hashes"],
            ["artifact:*.cef.destinationDnsDomain", "==", "custom_list:wannacry_domains"],
            ["artifact:*.cef.destinationAddress", "==", "custom_list:wannacry_ip_addrs"],
            ["artifact:*.cef.fileName", "==", "custom_list:wannacry_file_names"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        get_vm_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def prompt_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_4() called')
    
    # set user and message variables for phantom.prompt call
    user = "Automation Engineer"
    message = """The infected VM is:
{0}
Host Name: 
{1}

Do you want to 
1. Contain the threat  by terminating the process and blocking the hash?
2. Or do you want to revert the VM to last snapshot?"""

    # parameter list for template variable replacement
    parameters = [
        "get_vm_info:action_result.data.*.vm_full_name",
        "get_vm_info:action_result.data.*.vm_hostname",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "1",
                    "2",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_4", parameters=parameters, response_types=response_types, callback=decision_7)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_4:action_result.summary.responses.0", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        list_processes_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_4:action_result.summary.responses.0", "==", 2],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        revert_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_processes_3:action_result.data.*.name", "in", "custom_list:wannacry_file_names"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        terminate_malicious_process(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_hash_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_4' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_7:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_7:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_hash_4' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                'comment': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=filter_8, name="block_hash_4")

    return

def block_ip_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_4' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['block_hash_4:artifact:*.cef.sourceAddress', 'block_hash_4:artifact:*.id'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_8:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_8:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_ip_4' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        for inputs_item_1 in inputs_data_1:
            parameters.append({
                'dir': "out",
                'protocol': "",
                'remote_ip': filtered_artifacts_item_1[0],
                'rule_name': "",
                'ip_hostname': inputs_item_1[0],
                'remote_port': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="block ip", parameters=parameters, assets=['domainctrl1'], name="block_ip_4")

    return

def block_ip_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_5' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['block_hash_3:artifact:*.cef.destinationAddress', 'block_hash_3:artifact:*.cef.sourceAddress', 'block_hash_3:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_ip_5' call
    for inputs_item_1 in inputs_data_1:
        parameters.append({
            'dir': "out",
            'protocol': "",
            'remote_ip': inputs_item_1[0],
            'rule_name': "",
            'ip_hostname': inputs_item_1[1],
            'remote_port': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': inputs_item_1[2]},
        })

    phantom.act(action="block ip", parameters=parameters, assets=['domainctrl1'], name="block_ip_5")

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "in", "custom_list:wannacry_ip_addrs"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_9() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "in", "custom_list:wannacry_ip_addrs"],
        ],
        name="filter_9:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:wannacry_remediated_endpoints"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_vm_info:action_result.data.*.state", "==", "running"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def get_vm_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_vm_info() called')

    # collect data for 'get_vm_info' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_vm_info' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get system info", parameters=parameters, assets=['vmwarevsphere'], callback=decision_5, name="get_vm_info")

    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for container_item in container_data:
        parameters.append({
            'sensor_id': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="get system info", parameters=parameters, assets=['carbonblack'], callback=prompt_3, name="get_system_info_1")

    return

def list_processes_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_processes_3' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_processes_3' call
    for container_item in container_data:
        parameters.append({
            'sensor_id': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="list processes", parameters=parameters, assets=['carbonblack'], callback=filter_6, name="list_processes_3")

    return

def revert_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('revert_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'revert_vm_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_vm_info:action_result.data.*.vmx_path', 'get_vm_info:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'revert_vm_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'snapshot': "",
                'vmx_path': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="revert vm", parameters=parameters, assets=['vmwarevsphere'], name="revert_vm_1")

    return

def list_processes_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_processes_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_processes_2' call
    for container_item in container_data:
        parameters.append({
            'sensor_id': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="list processes", parameters=parameters, assets=['carbonblack'], callback=filter_4, name="list_processes_2")

    return

def deactivate_partition_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deactivate_partition_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deactivate_partition_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'deactivate_partition_1' call
    for container_item in container_data:
        parameters.append({
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="deactivate partition", parameters=parameters, assets=['domainctrl1'], callback=reboot_system_1, name="deactivate_partition_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    
    add_endpoint_to_remediated_list(container)
    
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return