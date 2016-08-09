"""
This is a sample playbook that can perform investigative actions on attacker IPs
and then retrieves malcious process from the infected machine and deploys it
on sandbox. 
Last updated by Phantom Team: August 09, 2016
"""
import phantom.rules as phantom
import json

def detonate_file_cb(action, success, offense, results, handle):

    if not success:
        return
    
    return

def get_process_file_cb(action, success, offense, results, handle):

    if not success:
        return
    
    parameters = []
    result_items = phantom.parse_success(results)
    for item in result_items:
        parameters.append({ "vault_id": item['vault_id'], 'file_name': item['name']})
    
    phantom.act('detonate file', parameters=parameters, assets=['Cuckoo'], callback=detonate_file_cb)

    return

def list_connections_cb(action, success, offense, results, handle):

    if not success:
        return
    
    attacker_ips = list(set(phantom.collect(offense, 'artifact:*.cef.sourceAddress', scope='all')))
    counter = 0

    for result in results:
        for action_result in result['action_results']:
            for data in action_result['data']:
                phantom.debug('on infected machine: '+str(action_result['parameter']['ip_hostname'])+' process connected to remote_ip: '+str(data['remote_ip']))
                if data['remote_ip'] in attacker_ips:    
                    phantom.debug('on infected machine found process connected to attacker_ip: '+str(data['remote_ip'])+' on port: '+str(data['remote_port']))
                    phantom.act('get process file', parameters=[{"pid":str(data['pid']), "ip_hostname" : action_result['parameter']['ip_hostname']}], assets=["AD"], callback=get_process_file_cb)    
                    return # for now returning with just one call to get process image
                    counter += 1
                    if counter == 3:
                        return
                
    phantom.debug("Attacker IP not found in list of connections. No process file to get.")
    return

def ip_reputation_cb(action, success, offense, results, handle):

    if not success:
        return

    victim_ips = list(set(phantom.collect(offense, 'artifact:*.cef.destinationAddress', scope='all')))
    parameters = []
    for ip in victim_ips:
        parameters.append({ "ip_hostname" : ip })
        
    phantom.act('list connections', parameters=parameters, assets=["AD"], callback=list_connections_cb, )

    return

def whois_ip_cb(action, success, offense, results, handle):

    if not success:
        return

    ips = set(phantom.collect(offense, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip })

    phantom.act('ip reputation', parameters=parameters, assets=["VT"], callback=ip_reputation_cb)

    return

def geolocate_ip_cb(action, success, offense, results, handle):

    if not success:
        return

    ips = set(phantom.collect(offense, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip })

    phantom.act('whois ip', parameters=parameters, assets=["whois"], callback=whois_ip_cb)

    return


def on_start(offense):

    ips = set(phantom.collect(offense, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip })

    phantom.act('geolocate ip', parameters=parameters, assets=["maxmind"], callback=geolocate_ip_cb)

    return

def on_finish(offense, summary):

    action_results = phantom.get_action_results(offense)

    phantom.debug("Action results: "+json.dumps(action_results))

    phantom.debug("Summary: " + summary)
    
    return

