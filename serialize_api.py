"""
This sample rule shows how to save an retrieve large amounts of data across rule runs using the save_data and get_data APIs. 
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
        phantom.act("file reputation", parameters=params, callback=generic_cb)

    # lets do geo lookup of attacker IPs
    params = []
    attacker_ips = phantom.attacker_ips(incident, scope='all')
    if len(attacker_ips) > 0:
        for ip in attacker_ips:
            params.append({'ip':ip})

        key = phantom.save_data(str(params))

        phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=key)

    return


def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if status else ' FAILED'))
    my_data = phantom.get_data(handle)
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  
