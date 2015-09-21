"""
This sample playbook shows using the API set_sensitivity and set_seveity
In this playbook, we get the users related to an incident and if any user is an executive list
we change the incident severity as high and sensitivity as high.

To run this playbook, create an list named 'executives' and add a user named 'Peggy'
and test this playbook against incident '2a76c74c-5713-11e4-8a26-9b99986c1e2a'

"""
import json
import phantom.rules as phantom

def on_start(incident):
    
    # lets do geo lookup of attacker IPs
    phantom.debug(incident['name'] + 'has severity: ' + incident['sensitivity'])
    phantom.debug(incident['name'] + 'has sensitivity: ' + incident['severity'])

    phantom.debug(' ------------------ USER NAMES --------------------------------- ')
    params = []
    victims = list(set(phantom.collect(incident, 'artifact:*.cef.sourceUserName', scope='all')))
    victims.extend(list(set(phantom.collect(incident, 'artifact:*.cef.destinationUserName', scope='all'))))

    if len(victims) > 0:
        exec_victims = []
        execs = phantom.datastore_get("executives")
        if execs is not None:
            exec_victims = [exec_info[0] for exec_info in execs if exec_info[0] in victims]
            
            if len(exec_victims) > 0:
                phantom.debug('Execs impacted by this incident: '+str(exec_victims))
                phantom.set_sensitivity(incident, 'amber')
                phantom.set_severity(incident, 'high')
    return




def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    phantom.debug(incident['name'] + 'has NEW severity: ' + incident['sensitivity'])
    phantom.debug(incident['name'] + 'has NEW sensitivity: ' + incident['severity'])
    return  


