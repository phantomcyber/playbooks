"""
This sample rule shows calling actions on an incident in a variety of ways
and also demonstrates the use of the API get_assets or get_asset_names

The actions are called with or without assets AND/OR tags

NOTE:
 If the list of assets happens to be an empty list, the action fails.

 If the intention is to execute the action on all possible assets that 
 support the action then assets have be specified as None or not passed 
 to phantom.act()
"""
import json
import phantom.rules as phantom

def on_start(incident):

    
    params = []
    hashes = list(set(phantom.collect(incident, 'artifact:*.cef.fileHash', scope='all')))
    if len(hashes) == 0:
        phantom.debug('No hashes found to act on')
        return

    for filehash in hashes:
        params.append({'hash':filehash})

    # action without specifying on assets executes action all matching assets using latest corresponding connectors/apps
    phantom.debug("1. calling action without specifying on assets executes action all matching assets using latest corresponding connectors/apps")
    phantom.act("file reputation", parameters=params, callback=generic_cb)

    # action on assets that support the action ..
    phantom.debug("2. calling action on specific assets that support the action 'file reputation'")
    selected_rep_assets=[]
    reputation_assets = phantom.get_assets(action="file reputation")
    for rep_asset in reputation_assets:
        selected_rep_assets.append(rep_asset["name"])

    #selected_rep_assets = phantom.get_asset_names(action="file reputation")
    phantom.act("file reputation", assets=selected_rep_assets, parameters=params, callback=generic_cb)

    # action on critical assets
    my_tags = []
    my_tags.append('Critical')
    phantom.debug("3. calling action with NO specific assets but tags 'Critical")
    phantom.act("file reputation", tags=my_tags, parameters=params, callback=generic_cb)

    # action on assets marked critical
    phantom.debug("4. calling action with any assets that were tagged 'Critical")
    critical_assets = phantom.get_asset_names(tags=my_tags)
    phantom.act("file reputation", assets=critical_assets, parameters=params, callback=generic_cb)

    # action on reputation assets marked critical
    phantom.debug("5. calling action with specific assets for the action that were taggged 'Critical")
    critical_reputation_assets = phantom.get_asset_names(action="file reputation", tags=my_tags)
    phantom.act("file reputation", assets=critical_reputation_assets, parameters=params, callback=generic_cb)

    # action on ALL assets
    phantom.debug("6. calling action on ALL assets!")
    all_assets = phantom.get_asset_names()
    phantom.act("file reputation", assets=all_assets, parameters=params, callback=generic_cb)

    # action on specified assets with specified tags
    phantom.debug("7. calling action on with specific assets and TAGs")
    phantom.act("file reputation", assets=selected_rep_assets, tags=my_tags, parameters=params, callback=generic_cb)
    return


def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if status else ' FAILED'))
    return


def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  
