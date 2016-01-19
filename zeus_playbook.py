"""This is a playbook for automating investigative and containment responses for Zeus infections. """

import phantom.rules as phantom
import json

# 1. If attacked machine is VM: take snapshot
# 2. Extract the malware file from the infected machine
# 3. On ThreatGrid sandbox, detonate the file 
# 4. If sandbox results show threat score of 60 or more, 
#        terminate any ongoing session using Cisco ISE
#        block the attacker IP on CISCO ASA
#        terminate the process on the endpoint
# 5. Block the malicious file on endpoint using SRP policies"""

def on_start(incident):
    
    phantom.debug("Local playbook")
    if 'Zeus' not in incident['name']:
        return
    phantom.act('list vms', callback=list_vms_cb)

def list_vms_cb(action, success, incident, results, handle):
    
    phantom.debug('VSphere list vms'+(' SUCCEEDED' if success else ' FAILED'))
    if not success:
        return
    attacked_ips = phantom.victim_ips(incident)
    
    phantom.debug(json.dumps(attacked_ips, indent=4))
    success_results = phantom.parse_success(results)
    for vm_info in success_results:
        if 'ip' in vm_info:# if the VM is running, it will have an IP
            if vm_info['ip'] in attacked_ips: #if the IP address of the VM is the attacked IP
                phantom.act('snapshot vm', parameters=[{'vmx_path':vm_info['vmx_path'],'download': False}], callback=generic_cb)
                
    if (attacked_ips):
        phantom.act('get process file', parameters=[{'name':'*infostealer*','ip_hostname':attacked_ips[0]}], assets=['domainctrl1'], callback=get_process_file_cb)
        
    else:
        phantom.debug("No new attacked_ips in list")
    
def get_process_file_cb(action, success, incident, results, handle):
    phantom.debug('get process file,'+(' SUCCEEDED' if success else ' FAILED'))
    if not success:
        return
    vault_id = results[0]['action_results'][0]['data'][0]['vault_id']
    phantom.act('detonate file', parameters=[{'vault_id':vault_id,'force_analysis':'false'}], assets=['threatgrid'], callback=detonate_file_cb)
    
def detonate_file_cb(action, success, incident, results, handle):
    phantom.debug('ThreatGrid action to detonate file,'+(' SUCCEEDED' if success else ' FAILED'))
    if not success:
        return
    score = results[0]['action_results'][0]['data'][0]['threat']['score']
    phantom.debug('ThreatGrid threat score for this file: '+str(score))
    if score > 60:
        for mac_addr in phantom.collect(incident,'artifact:*.cef.sourceMacAddress'):
            phantom.act('terminate session', parameters=[{'macaddress':mac_addr}], assets=['ciscoise'], callback=generic_cb)
        for a_ip in phantom.attacker_ips(incident):
            params = [{'src':'any','direction':'out','dest':a_ip,'interface':'outside','access-list':'inside_access_out'}]
            phantom.act('block ip', parameters=params, assets=['ciscoasa'], callback=generic_cb)
        for v_ip in phantom.victim_ips(incident):
            phantom.act('terminate process', parameters=[{'name':'*infostealer*','ip_hostname':v_ip}], assets=['domainctrl1'], callback=terminate_process_cb)
    
def terminate_process_cb(action, status, incident, results, handle):
    phantom.debug('terminate process,'+ (' SUCCEEDED' if status else ' FAILED'))
    attacked_ips = phantom.victim_ips(incident) 
    phantom.act('block path',[{'path':'infostealer*', "ip_hostname": attacked_ips[0]}], callback=generic_cb, assets=['domainctrl1']) 

def generic_cb(action, status, incident, results, handle):
    
    
    phantom.debug(action['action_name'] + (', SUCCEEDED' if status else ', FAILED'))
    
def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  
