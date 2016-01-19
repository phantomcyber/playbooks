"""
This playbook demonstrates all the actions supported by the OpenDNS Umbrella app.
"""

import phantom.rules as phantom
import json
import simplejson as json
from datetime import datetime
from datetime import timedelta 


def add_domains_to_block_list():
    
    parameters = [{'domain': 'yahoo.com', 'disable_safeguards': True}, {'domain': 'msn.com', 'disable_safeguards': True}]
    
    phantom.act('block domain', parameters=parameters, assets=['opendns_umbrella'], callback=block_domains_cb)
    
    return


def check_domain_connectivity_cb(action, success, incident, results, handle):

    if not success:
        return
    
    success_list = phantom.parse_success(results)
    
    # Dump the results of the ping command, the ip address of the domain pinged will change if it is blocked or not.
    phantom.debug("Results:\n{0}".format(json.dumps(success_list, indent=4 * ' ')))
    
    if (handle is None):
        return
    
    handle_dict = json.loads(handle)
    
    add_block = handle_dict['add_block']
    
    if (add_block):
        add_domains_to_block_list()
    
    return


def check_domain_connectivity(delay=False, add_block=True):
    """ This function pings a static domain. If delay is True, then waits for a few minutes before pinging, this delay is to allow the config change that results from an action to take place"""
    when = datetime.now()+timedelta(seconds=5)
    
    if (delay):
        # Do after 3 minutes
        when = datetime.now()+timedelta(seconds=60*3)
        
    handle_dict = {'add_block': add_block}
        
    phantom.act("execute program", parameters=[{'ip_hostname': '10.17.1.49', 'program': 'ping', 'args': 'www.yahoo.com'}], callback=check_domain_connectivity_cb, assets=['domainctrl1'], handle=json.dumps(handle_dict), start_time=when)
    
    return

def block_domains_cb(action, success, incident, results, handle):

    if not success:
        return
    
    # Check the domain connectivity, the output of the ping command should display the OpenDNS Sink ip of the domain being pinged. That means the domain is blocked.
    check_domain_connectivity(delay=True, add_block=False)

    return

def unblock_domains_cleanup_cb(action, success, incident, results, handle):

    if not success:
        return
    
    # Check the domain connectivity, the output of the ping command should display the real ip of the domain being pinged.
    check_domain_connectivity(delay=True)

    return

def list_blocked_domains_cb(action, success, incident, results, handle):

    if not success:
        return
    
    success_list = phantom.parse_success(results)
    
    phantom.debug("Domain Block List:\n{0}".format(json.dumps(success_list, indent=4 * ' ')))
    
    
    # unblock all of them, start with a clean slate.
    parameters = []
    for domain_entry in success_list:
        domain = domain_entry['name']
        parameters.append({'domain': domain})
    
    if (parameters):
        phantom.act('unblock domain', parameters=parameters, assets=['opendns_umbrella'], callback=unblock_domains_cleanup_cb)
    else:
        check_domain_connectivity()

    return


def on_start(incident):

    # list all the blocked domains, if any
    phantom.act('list blocked domains', parameters=[{ }], assets=['opendns_umbrella'], callback=list_blocked_domains_cb)

    return


def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return