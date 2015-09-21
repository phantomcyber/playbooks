"""
This is a sample playbook that can perform simple investigative actions on various pieces of information
in the events of an incident. 
"""
import json
import phantom.rules as phantom

def on_start(incident):

    phantom.debug('---------- ANALYZING FILE HASHES ----------')
    params = []
    hashes = list(set(phantom.collect(incident, 'artifact:*.cef.fileHash', scope='all')))
    
    if len(hashes) > 0:
    	for filehash in hashes:
      		params.append({'hash':filehash})
    	phantom.act("file reputation", parameters=params, callback=generic_cb)
  
  	phantom.debug('---------- ANALYZING ATTACKER IPs ----------')
    params = []
    attacker_ips = phantom.attacker_ips(incident, scope='all')
    if len(attacker_ips) > 0:
    	for ip in attacker_ips:
        	params.append({'ip':ip})
        phantom.act("geolocate ip", parameters=params, callback=generic_cb)
    
    phantom.debug('---------- ANALYZING VICTIM IPs ----------')
    # lets do system info for infected machines
    params = []
    victim_ips = phantom.victim_ips(incident, scope='all')
    if len(victim_ips) > 0:
        for ip in victim_ips:
            params.append({'ip_hostname':ip})
        phantom.act("get system info", parameters=params, callback=generic_cb)
    
    
    phantom.debug('---------- ANALYZING USERs ----------')
    params = []
    victims = list(set(phantom.collect(incident, 'artifact:*.cef.sourceUserName', scope='all')))
    victims.extend(list(set(phantom.collect(incident, 'artifact:*.cef.destinationUserName', scope='all'))))

    execs = phantom.datastore_get("executives")
    if ((len(execs) > 0) and (len(victims) > 0)):
        exec_victims = [exec_info[0] for exec_info in execs if exec_info[0] in victims]
        if len(exec_victims) > 0:
            phantom.set_severity(incident, 'high')
            phantom.set_sensitivity(incident, 'amber')
        for victim in victims:
            params.append({'username':victim})
        phantom.act("list user groups", parameters=params, callback=generic_cb)

    phantom.debug('---------- ANALYZING URLs ----------')
    params = []
    events=[]
    events = phantom.collect(incident, 'artifact:event', scope='all')
    urls = []
    urls = phantom.get_URLs(incident, scope='all', events=events)
    if len(urls) > 0:
        for url in urls:
            params.append({'domain':url})
        phantom.act("whois domain", parameters=params, callback=generic_cb)
    return


def generic_cb(action, success, incident, results, handle):
    phantom.debug('Action '+action+ (' SUCCEEDED' if success else ' FAILED'))
    return


def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  





