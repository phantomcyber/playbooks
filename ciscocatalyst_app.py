"""
This playbook runs the Cisco Catalyst actions.
Last updated by Phantom Team: May 19, 2016
"""

import phantom.rules as phantom
import json

def set_system_vlan_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def set_system_vlan1_cb(action, success, incident, results, handle):

    if not success:
        return

    ip_macaddresss = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip_macaddress in ip_macaddresss:
        parameters.append({ "ip_macaddress" : ip_macaddress,  "ping_ip" : False,  "vlan_id" : "160", "override_trunk" : False })

    if parameters:
        phantom.act('vlan host', parameters=parameters, assets=["ciscocatalyst"], callback=set_system_vlan_cb)

    return

def set_system_vlan2_cb(action, success, incident, results, handle):

    if not success:
        return

    ip_macaddresss = set(phantom.collect(incident, 'artifact:*.cef.sourceMacAddress', scope='all'))

    parameters = []

    for ip_macaddress in ip_macaddresss:
        parameters.append({ "ip_macaddress" : ip_macaddress,  "ping_ip" : False,  "vlan_id" : "160",  "override_trunk" : False })

    if parameters:
        phantom.act('vlan host', parameters=parameters, assets=["ciscocatalyst"], callback=set_system_vlan1_cb)

    return


def on_start(incident):

    ip_macaddresss = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip_macaddress in ip_macaddresss:
        parameters.append({ "ip_macaddress" : ip_macaddress,  "ping_ip" : True,  "vlan_id" : "170",  "override_trunk" : False })

    if parameters:
        phantom.act('vlan host', parameters=parameters, assets=["ciscocatalyst"], callback=set_system_vlan2_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
