"""
Hunt for wannacry IOCs (maintained in an external custom list) file, domain, and IP indicators in network and create tickets.
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

    # call 'hunt_file_1' block
    hunt_file_1(container=container)

    # call 'list_endpoints_1' block
    list_endpoints_1(container=container)

    return

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_endpoints_1:action_result.data.*.ips", "not in", "custom_list:wannacry_infected_endpoints"],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        list_connections_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket_description')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Wanna Cry Hunting Campaign Result",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_1")

    return

def list_connections_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_connections_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'list_connections_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['list_endpoints_1:action_result.data.*.ips', 'list_endpoints_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'list_connections_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'pid': "",
            'ip_hostname': results_item_1[0],
            'process_name': "",
            'carbonblack_process_id': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="list connections", parameters=parameters, assets=['carbonblack'], callback=filter_matching_IP, name="list_connections_1")

    return

def list_endpoints_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_endpoints_1() called')

    parameters = []

    phantom.act(action="list endpoints", parameters=parameters, assets=['carbonblack'], callback=filter_7, name="list_endpoints_1")

    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.process.results.*.sensor_id', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'sensor_id': results_item_1[0],
            'ip_hostname': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="get system info", parameters=parameters, assets=['carbonblack'], callback=filter_6, name="get_system_info_1", parent_action=action)

    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_1() called')

    # get custom list for wannacry_hashes
    cl_wannacry_hashes = phantom.datastore_get('wannacry_hashes')

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for wannacry_hash in cl_wannacry_hashes:
        if wannacry_hash:
            parameters.append({
                'hash': wannacry_hash,
                'range': "",
                'type': "",
            })

    phantom.act("hunt file", parameters=parameters, assets=['carbonblack'], callback=get_system_info_1, name="hunt_file_1")    
    
    return

def filter_matching_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_matching_IP() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_connections_1:action_result.data.*.ip_addr", "in", "custom_list:wannacry_ip_addrs"],
        ],
        name="filter_matching_IP:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_format_ticket_description(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_system_info_1:action_result.data.*.ips", "not in", "custom_list:wannacry_infected_endpoints"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_format_ticket_description(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
List the IP addresses and file hashes in a formatted paragraph for the ticket description.
"""
def format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_description() called')
    
    template = """The following endpoints have active connections with IP addresses associated with wannacry: 
{0}

The following endpoints have a wannacry fileHash present on their system: 
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_matching_IP:condition_1:list_connections_1:action_result.data.*.hostname",
        "hunt_file_1:action_result.data.*.process.results.*.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_description")

    create_ticket_1(container=container)

    return

def join_format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_ticket_description() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['list_connections_1', 'get_system_info_1']):
        
        # call connected block "format_ticket_description"
        format_ticket_description(container=container, handle=handle)
    
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