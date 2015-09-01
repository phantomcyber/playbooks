"""
This sample rule shows calling one or more actions on an incident
and evaluating the outcome in a generic callback.

The use passes a 'handle' to the action which is returned back in
the callback. 'handle' must be a string. It can be any data, however
if the length of the data exceeds 4k, it will fail. Alternatively, user
can use the save_data and get_data apis to save the data and get a key 
which can be the handle and then later retrieve the data using the key
and get_data api. Refer to simple_rule_using_serialization for usage
example of save_data and get_data apis
"""
import json
import phantom.rules as phantom

def on_start(incident):
    # lets do VT lookup of file hashes in the artifacts of an incident
    params = []
    hashes = list(set(phantom.collect(incident, 'artifact:*.cef.fileHash', scope='all')))
    if len(hashes) > 0:
        for filehash in hashes:
            params.append({'hash':filehash})
        phantom.act("file reputation", parameters=params, callback=generic_cb, name='my_file_lookup_action')

    # lets do geo lookup of attacker IPs
    params = []
    attacker_ips = phantom.attacker_ips(incident, scope='all')
    if len(attacker_ips) > 0:
        for ip in attacker_ips:
            params.append({'ip':ip})
        phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params))
    return


def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if status else ' FAILED'))
    phantom.debug('My Handle: '+handle)
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

