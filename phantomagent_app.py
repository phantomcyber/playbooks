"""
This playbook runs all the phantomagent actions one by one.
"""
import phantom.rules as phantom
import json

def reboot_system_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def logoff_user_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('reboot system', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=reboot_system_cb)

    return

def list_sessions_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('logoff user', parameters=[{ "username" : "CORP\\User1",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=logoff_user_cb)

    return

def terminate_process_cb(action, success, incident, results, handle):

    phantom.act('list sessions', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=list_sessions_cb)

    return

def get_process_dump_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('terminate process', parameters=[{ "name" : "chrome.exe",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=terminate_process_cb)

    return

def get_process_file_cb(action, success, incident, results, handle):

    phantom.act('get process dump', parameters=[{ "name" : "notepad.exe",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=get_process_dump_cb)

    return

def list_processes_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get process file', parameters=[{ "name" : "notepad.exe",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=get_process_file_cb)

    return

def list_connections_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list processes', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=list_processes_cb)

    return

def activate_partition_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list connections', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=list_connections_cb)

    return

def deactivate_partition_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('activate partition', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=activate_partition_cb)

    return

def list_srps_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('deactivate partition', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=deactivate_partition_cb)

    return

def list_firewall_rules_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list srps', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=list_srps_cb)

    return

def delete_firewall_rule_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list firewall rules', parameters=[{ "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=list_firewall_rules_cb)

    return

def block_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('delete firewall rule', parameters=[{ "rule_name" : "ph_block_rule_AAB123",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=delete_firewall_rule_cb)

    return

def delete_srp_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('block ip', parameters=[{ "protocol" : "tcp",  "remote_port" : "22",  "ip_hostname" : "10.17.1.44",  "rule_name" : "ph_block_rule_AAB123",  "dir" : "out",  "remote_ip" : "192.94.73.9" }], assets=["domainctrl1"], callback=block_ip_cb)

    return

def block_path_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('delete srp', parameters=[{ "guid" : results[0]['action_results'][0]['data'][0]['guid'],  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=delete_srp_cb)

    return

def delete_srp1_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('block path', parameters=[{ "path" : "infostealer*",  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=block_path_cb)

    return

def block_hash_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('delete srp', parameters=[{ "guid" : results[0]['action_results'][0]['data'][0]['guid'],  "ip_hostname" : "10.17.1.44" }], assets=["domainctrl1"], callback=delete_srp1_cb)

    return


def on_start(incident):

    phantom.act('block hash', parameters=[{ "hash" : "7a0dfc5353ff6de7de0208a29fa2ffc9",  "ip_hostname" : "10.17.1.44",  "file_size" : "495616" }], assets=["domainctrl1"], callback=block_hash_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

