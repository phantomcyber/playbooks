"""
This rule runs all the ldap actions one by one.
"""

import phantom.rules as phantom
import json

def get_system_attributes_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def get_user_attributes_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get system attributes', parameters=[{ "hostname" : "winxpprox87" }], assets=["domainctrl1"], callback=get_system_attributes_cb)

    return

def set_system_attribute_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get user attributes', parameters=[{ "username" : "jason_malware" }], assets=["domainctrl1"], callback=get_user_attributes_cb)

    return

def change_system_ou_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('set system attribute', parameters=[{ "attribute_value" : "admin,Office,NYC",  "hostname" : "winxpprox87",  "attribute_name" : "extensionattribute1" }], assets=["domainctrl1"], callback=set_system_attribute_cb)

    return

def change_system_ou1_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('change system ou', parameters=[{ "ou" : "computers",  "hostname" : "winxpprox87" }], assets=["domainctrl1"], callback=change_system_ou_cb)

    return

def enable_user_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('change system ou', parameters=[{ "ou" : "staging",  "hostname" : "winxpprox87" }], assets=["domainctrl1"], callback=change_system_ou1_cb)

    return

def disable_user_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('enable user', parameters=[{ "username" : "jason_malware" }], assets=["domainctrl1"], callback=enable_user_cb)

    return


def on_start(incident):

    phantom.act('disable user', parameters=[{ "username" : "jason_malware" }], assets=["domainctrl1"], callback=disable_user_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

