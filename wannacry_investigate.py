"""
Investigate endpoints associated with events that successfully match against the wannacry IOCs (file, domain, and IP indicators) maintained in external custom lists and update severity and create tickets accordingly
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
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

    decision_2(container=container)

    return

def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_1() called')

    # collect data for 'list_processes_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_processes_1' call
    for container_item in container_data:
        parameters.append({
            'sensor_id': "",
            'ip_hostname': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="list processes", parameters=parameters, assets=['carbonblack'], callback=join_format_ticket, name="list_processes_1")

    return

def set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_2() called')

    phantom.set_status(container=container, status="open")

    return

def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_system_info_2:action_result.data.*.vmx_path', 'get_system_info_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'download': "",
                'vmx_path': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="snapshot vm", parameters=parameters, assets=['vmwarevsphere'], callback=join_format_ticket, name="snapshot_vm_1", parent_action=action)

    return

def get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_2() called')

    # collect data for 'get_system_info_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_system_info_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get system info", parameters=parameters, assets=['vmwarevsphere'], callback=snapshot_vm_1, name="get_system_info_2")

    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_1() called')

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

    phantom.act(action="get system info", parameters=parameters, assets=['carbonblack'], callback=get_system_info_1_callback, name="get_system_info_1")

    return

def get_system_info_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_system_info_1_callback() called')
    
    update_infected_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    join_format_ticket(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')

    # collect data for 'list_connections_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for container_item in container_data:
        parameters.append({
            'pid': "",
            'ip_hostname': container_item[0],
            'process_name': "",
            'carbonblack_process_id': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="list connections", parameters=parameters, assets=['carbonblack'], callback=join_format_ticket, name="list_connections_1")

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Confirmed Wannacry Event",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=set_severity_status_1, name="create_ticket_1")

    return

def set_severity_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_status_1() called')

    phantom.set_severity(container=container, severity="high")

    phantom.set_status(container=container, status="closed")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:wannacry_infected_endpoints"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "in", "custom_list:wannacry_hashes"],
            ["artifact:*.cef.destinationDnsDomain", "in", "custom_list:wannacry_domains"],
            ["artifact:*.cef.destinationAddress", "in", "custom_list:wannacry_ip_addrs"],
            ["artifact:*.cef.fileName", "in", "custom_list:wannacry_file_names"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        list_connections_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        list_processes_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_status_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def update_infected_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updated_infected_list() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'updated_infected_list' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['get_system_info_1:artifact:*.cef.sourceAddress', 'get_system_info_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'updated_infected_list' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            phantom.datastore_add('wannacry_infected_endpoints', [ inputs_item_1[0] ] )
    
    return

"""
Format action result data in preparation for creating a ticket.
"""
def format_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket() called')
    
    template = """VM Snapshots have been taken.  They are stored at the following vault IDs:
{0}

Total number of endpoints affected:
{1}

Full list_connections results from Carbon Black:
{2}

Full list_processes results from Carbon Black:
{3}

Full system info results from Carbon Black:
{4}"""

    # parameter list for template variable replacement
    parameters = [
        "snapshot_vm_1:action_result.data.*.vault_id",
        "get_system_info_1:action_result.summary.total_endpoints",
        "list_connections_1:action_result",
        "list_processes_1:action_result",
        "get_system_info_1:action_result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket")

    create_ticket_1(container=container)

    return

def join_format_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_ticket() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['snapshot_vm_1', 'list_processes_1', 'list_connections_1', 'get_system_info_1']):
        
        # call connected block "format_ticket"
        format_ticket(container=container, handle=handle)
    
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