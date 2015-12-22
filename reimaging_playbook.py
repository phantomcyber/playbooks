"""
This is a playbook that carries out various actions related to re-imaging a system via Windows Deployment Services.
"""

import json
import phantom.rules as phantom

# Testing with incident cc613d81-cde6-442d-bdfc-f53b26363b5a

def on_start(incident):

    machines = list()

    # get the artifacts, which is of type 'event'
    events = phantom.get_artifacts(incident, artifact_label='event')

    # loop through each event
    for i, event in enumerate(events):
        phantom.debug('Working on event # {0}'.format(i))
        phantom.debug('Event: \n{0}'.format(event))

        # Create the dictionary, that will serve as the handle for a machine
        machine = {'ip':event['cef']['sourceAddress'], 'name':event['cef']['sourceHostName']}

        # Add it to the list if not present
        if machine not in machines:
      	    machines.append(machine)
    
    # Dump it
    phantom.debug('Found {0} machines, details: {1}'.format(len(machines), machines))
    
    if (len(machines) == 0):
        # Nothing to do
        phantom.debug('No machines found Returned')
        return

    # Now go through each machine and work on them
    for i, machine in enumerate(machines):
        phantom.debug("Working on Machine # {0} with ip: '{1}' and name '{2}'".format(
            i, machine['ip'], machine['name']))

        # params list for getting the attributes
        params = []
    
        params.append({'hostname':machine['name']})
    
        phantom.act("get system attributes", parameters=params, assets=['domainctrl2'],
                callback=get_system_attrib_cb, handle=str(machine))
    
    return

def get_system_attrib_cb(action, status, incident, results, handle):
    """Callback for the get system attribute action"""

    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if status else ' FAILED')))

    if (status == False):
        return

    # get the handle which is the machine info
    machine = eval(handle)
    
    phantom.debug("Working on '{0}' with ip '{1}'".format(machine['name'], machine['ip']))
    success_list = phantom.parse_success(results)
		
    phantom.debug('success_list: ' + str(success_list))
    phantom.debug('results: ' + str(results))
    
    params = []

    # We are carrying out the action for a single machine at a time, so there will be only one machine_info
    machine_info = success_list[0]
    phantom.debug('Machine: {0} is {1}'.format(machine_info['name'], machine_info['operatingSystem']))

    # Add the netbootmirrordatafile variable value
    params.append({'hostname':machine_info['name'], 
        'attribute_name':'netbootmirrordatafile',
        'attribute_value':'BootImagePath=Boot\\x64\\Images\\boot.wim;WdsUnattendFilePath=WDSClientUnattend\\WDSClientUnattend.xml;JoinDomain=1;'})

    # Add the extensionattribute1 variable value
    params.append({'hostname':machine_info['name'], 
        'attribute_name':'extensionattribute1',
        'attribute_value':'admin,Office,NYC,Y'})

    phantom.act("set system attribute", parameters=params, assets=['domainctrl2'], 
            callback=set_system_attrib_cb, handle=handle)
    
    return

def set_system_attrib_cb(action, status, incident, results, handle):
    """Callback for the set system attribute action"""

    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if status else ' FAILED')))
    
    if (status == False):
        return
    
    # get the handle which is the machine info
    machine = eval(handle)
    phantom.debug("Working on '{0}' with ip '{1}'".format(machine['name'], machine['ip']))

    # Now we have to move the machine to another OU
    params = []
    params.append({'ou':'staging', 'hostname':machine['name']})
    
    phantom.act('change system ou', parameters=params, assets=['domainctrl2'], 
            callback=change_system_ou_cb, handle=handle)
    
    return
  
def change_system_ou_cb(action, status, incident, results, handle):
    """Callback for the change system ou action"""

    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if status else ' FAILED')))

    if (status == False):
        return

    # get the handle which is the machine info
    machine = eval(handle)
    phantom.debug("Working on '{0}' with ip '{1}'".format(machine['name'], machine['ip']))

    # Now mark the system inactive, use the ip address here.
    params = []
    params.append({'ip_hostname':machine['ip']})
    
    phantom.act('deactivate partition', parameters=params, assets=['domainctrl2'], 
            callback=sys_part_inactive_cb, handle=handle)

    return
    
def sys_part_inactive_cb(action, status, incident, results, handle):
    """Callback for the deactivate partition action"""
    
    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if status else ' FAILED')))

    if (status == False):
        return

    # get the handle which is the machine info
    machine = eval(handle)
    phantom.debug("Working on '{0}' with ip '{1}'".format(machine['name'], machine['ip']))
    
    # Now reboot the system that was marked inactive
    params = []
    params.append({'ip_hostname':machine['ip']})
    
    phantom.act('reboot system', parameters=params, assets=['domainctrl2'], 
            callback=reboot_system_cb, handle=handle)

    return
  
def reboot_system_cb(action, status, incident, results, handle):
    """Callback for the reboot system action"""

    phantom.debug('Action: {0} {1}'.format(action['action_name'], (' SUCCEEDED' if status else ' FAILED')))

    machine = eval(handle)

    # reboot done
    phantom.debug("reboot_system_cb on '{0}' with ip '{1}'".format(machine['name'], machine['ip']))

    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

