"""
This sample playbook shows the usage of phantom.collect API.
"""
import json
import phantom.rules as phantom

def on_start(incident):
    # lets do VT lookup of file hashes in the artifacts of an incident
    #      artifacts:event.cef.fileHash
    #      artifacts:event.cef.*
    #      artifacts:event.raw.*
    #      artifacts:event.*

    hashes = phantom.collect(incident, 'artifact:*.cef.fileHash', 'all', 100)
    phantom.debug('1:'+str(hashes))

    #hashes = phantom.collect(incident, 'artifact:*.*.fileHash', 'all', 100)
    #phantom.debug('2:'+str(hashes))

    #hashes = phantom.collect(incident, 'artifact:*.cef.*', 'all', 100)
    #phantom.debug('3:'+str(hashes))

    #hashes = phantom.collect(incident, 'artifact:*.raw.*', 'all', 100)
    #phantom.debug('4:'+str(hashes))

    #hashes = phantom.collect(incident, 'artifact:*.*', 'all', 100)
    #phantom.debug('5:'+str(hashes))
    
    #hashes = phantom.collect(incident, 'artifact:*.source_data_identifier', 'all', 100)
    #phantom.debug('6:'+str(hashes))

    #hashes = phantom.collect(incident, '*', 'all', 100)
    #phantom.debug('7:'+str(hashes))
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  
