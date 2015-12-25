"""
This is a playbook for performing who-is lookups on IPs in incidents.
"""
import json
import phantom.rules as phantom

def on_start(incident):
    attacker_ips = phantom.attacker_ips(incident, scope='all')
    if len(attacker_ips) <= 0:
        phantom.debug('No attacker IP in events')
    else:
        params = []
        for ip in attacker_ips:
            params.append({'ip':ip})
        phantom.act("whois ip", parameters=params, callback=whois_cb)
    return

def whois_cb(action, success, incident, results, handle):
    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if success else ' FAILED')))
    if not success:
        return

    success_results = phantom.parse_success(results)
    for result in success_results:
        phantom.debug('IP: '+str(result['query'])+' is in Country: '+str(result['asn_country_code']))
    
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  



