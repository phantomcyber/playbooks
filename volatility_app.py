"""
This playbook runs all the Volatility App actions one by one.
Last updated by Phantom Team: May 19, 2016
"""

import phantom.rules as phantom
import json

def get_registry_key_callback(action, success, incident, results, handle):

    if not success:

        phantom.debug('get registry key action failed')

    return

def get_registry_hives_callback(action, success, incident, results, handle):

    if not success:

        phantom.debug('get registry hives action failed')

        return

    #IMPORTANT: iterate through the results of the 'get registry hives' action to find the hive to search in. In the code below, we are not passing the hive_address parameter to search in, hence this code will search for the key in all hives.

    phantom.act('get registry key' , parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'], "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'], 'key':'Software\Microsoft\Windows\CurrentVersion' }], assets=["volatility"], callback=get_registry_key_callback)

    return

def get_command_history_callback(action, success, incident, results, handle):

    if not success:

        phantom.debug('get command history action failed')

        return

    vault_id = results[0]['action_results'][0]['data'][0]['vault_id']

    my_vault_file = phantom.get_vault_file(vault_id)

    data = my_vault_file.read()

    phantom.debug(data)

    phantom.act('get registry hives' , parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'], "vault_id" : results[0]['action_results'][0]['parameter']['vault_id']}], assets=["volatility"], callback=get_registry_hives_callback)

    return

def list_open_files_callback(action, success, incident, results, handle):

    phantom.act('get command history' , parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'], "vault_id" : results[0]['action_results'][0]['parameter']['vault_id']}], assets=["volatility"], callback=get_command_history_callback)

def get_process_file_cb(action, success, incident, results, handle):


    phantom.act('list open files' , parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'], "vault_id" : results[0]['action_results'][0]['parameter']['vault_id']}], assets=["volatility"], callback=list_open_files_callback)

    return

def list_processes_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get process file', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'],  "pid" : "2667" }], assets=["volatility"], callback=get_process_file_cb)

    return

def list_mfts_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list processes', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_processes_cb)

    return

def get_timeline_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list mfts', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_mfts_cb)

    return

def list_mrus_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get timeline', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=get_timeline_cb)

    return

def get_browser_history_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list mrus', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_mrus_cb)

    return

def list_sockets_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get browser history', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=get_browser_history_cb)

    return

def find_malware_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list sockets', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_sockets_cb)

    return

def list_mutexes_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('find malware', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=find_malware_cb)

    return

def list_drivers_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list mutexes', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_mutexes_cb)

    return

def list_connections_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list drivers', parameters=[{ "profile" : results[0]['action_results'][0]['summary']['vol_profile_used'],  "vault_id" : results[0]['action_results'][0]['parameter']['vault_id'] }], assets=["volatility"], callback=list_drivers_cb)

    return

def snapshot_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list connections', parameters=[{ "vault_id" : results[0]['action_results'][0]['summary']['vault_id'] }], assets=["volatility"], callback=list_connections_cb)

    return

def on_start(incident):

    phantom.act('snapshot vm', parameters=[{ "download" : "True",  "vmx_path" : "[ha-datacenter][DAS_labesxi7_1] WXP3x86/WXP3x86.vmx" }], assets=["vmwarevsphere"], callback=snapshot_vm_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: "+summary)

    return  

