"""
This sample playbook shows how an analyst can be involved in automated actions where he/she can
review the params of the action before it can be executed. The analyst can allow
or deny the action from executing in the approval process, or the analyst can alter the 
params before allowing the action from executing.
"""
import phantom.rules as phantom

def on_start(incident):
    # lets do VT lookup of file hashes
    params = []
    hashes = list(set(phantom.collect(incident, 'artifact:*.cef.fileHash', scope='all')))
    if len(hashes) == 0:
        return

    for filehash in hashes:
        params.append({'hash':filehash})

    # specify the reviewer to review the prameters of the action before it is executed
    phantom.act("file reputation", parameters=params, callback=generic_cb, reviewer='admin@phantom.us')
    return

def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if results else ' FAILED'))
    return


def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

