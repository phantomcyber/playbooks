"""
Demonstrate updating the Heads-Up Display from a Playbook using a variety of indicator types, styles, and sizes.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

def is_ioc(value):
    import phantom.utils as phutils
    
    ioc_funcs = [phutils.is_ip, phutils.is_url, phutils.is_email, phutils.is_hash]
    for f in ioc_funcs:
        if f(value):
            return True, f.__name__.split('_')[1]
    return False, None


def pin_name_mangle(pin_name, container):
    return pin_name + '__{0}'.format(container['id'])

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    pin_1(container=container)
    pin_2(container=container)
    pin_3(container=container)
    pin_4(container=container)

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    import random
    phantom.debug('pin_3() called')

    # collect data for 'pin_to_hud_6' call
    dest_domain = [x for x in phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain']) if x[0]]
    
    pin_name = pin_name_mangle("pin_3", container)
    
    try:
        most_rcnt_domain = dest_domain[0][0]
    except:
        pass
    else:
        pin_id = phantom.get_data(pin_name)
        if not pin_id:
            ret_val, message, pin_id = phantom.pin(container=container, message="Most Recent Domain", data=most_rcnt_domain, pin_type="card_medium", pin_style="red")
            phantom.debug("new pin_3")
        else:
            ret_val, message = phantom.update_pin(pin_id, message="Most Recent Domain", data=most_rcnt_domain, pin_type="card_medium", pin_style="red")
        if ret_val:
            phantom.save_data(pin_id, pin_name)

    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)
    return

def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    import random
    phantom.debug('pin_1() called')

    # collect data for 'pin_to_hud_6' call
    dest_ip_artifacts = [x for x in phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress']) if x[0]]
    sorc_ip_artifacts = [x for x in phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress']) if x[0]]

    styles = set(["white", "red", "purple"])
    
    pin_name = pin_name_mangle("pin_1", container)
    pin_id = phantom.get_data(pin_name)
    
    if not pin_id:
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected IPs", data=str(len(dest_ip_artifacts) + len(sorc_ip_artifacts)), pin_type="card_medium", pin_style="white")
        phantom.debug("new pin_1")
    else:
        style = random.sample(styles, 1)[0]
        phantom.debug(style)
        ret_val, message = phantom.update_pin(pin_id, message="Affected IPs", data=str(len(dest_ip_artifacts) + len(sorc_ip_artifacts)), pin_style=style)
    
    if ret_val:
        phantom.save_data(pin_id, pin_name)

    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)

    return

def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    import random
    phantom.debug('pin_2() called')

    # collect data for 'pin_to_hud_6' call
    dest_username = [x for x in phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName']) if x[0]]
    sorc_username = [x for x in phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName']) if x[0]]

    styles = set(["white", "red", "purple"])
    pin_name = pin_name_mangle("pin_2", container)
    pin_id = phantom.get_data(pin_name)
    
    if not pin_id:
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected Users", data=str(len(dest_username) + len(sorc_username)), pin_type="card_medium", pin_style="purple")
        phantom.debug("new pin_2")
    else:
        # Delete and remake this one, for the sake of demonstration
        ret_val, message = phantom.delete_pin(pin_id)
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected Users", data=str(len(dest_username) + len(sorc_username)), pin_type="card_medium", pin_style=random.sample(styles, 1)[0])
    
    if ret_val:
        phantom.save_data(pin_id, pin_name)
    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)

    return

def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_4() called')
    artifacts = phantom.collect(container=container, datapath='artifacts:*', scope='all')
    artifacts = sorted(artifacts, key = lambda x: x['update_time'], reverse=True)
    
    ioc_count = 0
    most_recent_ioc = None
    ioc_types = set()

    for artifact in artifacts:
        for key, value in artifact['cef'].items():
            value = str(value)
            ret, ioc_type = is_ioc(value)
            if ret:
                if most_recent_ioc is None:
                    most_recent_ioc = value
                ioc_count += 1
                ioc_types.add(ioc_type)
    
    pin4_name = pin_name_mangle("pin_4", container)
    pin5_name = pin_name_mangle("pin_5", container)
    pin6_name = pin_name_mangle("pin_6", container)
    
    pin_id_ioc_cnt = phantom.get_data(pin4_name)
    pin_id_ioc_rct = phantom.get_data(pin5_name)
    pin_id_ioc_type = phantom.get_data(pin6_name)
    
    if not pin_id_ioc_cnt:
        ret_val, message, pin_id_ioc_cnt = phantom.pin(container=container, message="IOC Count", data=str(ioc_count), pin_type="card_medium", pin_style="white")
    else:
        ret_val, message = phantom.update_pin(pin_id_ioc_cnt, message="IOC Count", data=str(ioc_count), pin_type="card_medium", pin_style="red")
    if ret_val:
        phantom.save_data(pin_id_ioc_cnt, pin4_name)
    
    if ioc_count:
        if not pin_id_ioc_rct:
            ret_val, message, pin_id_ioc_rct = phantom.pin(container=container, message="Most Recent IOC", data=most_recent_ioc, pin_type="card_medium", pin_style="purple")
        else:
            ret_val, message = phantom.update_pin(pin_id_ioc_rct, message="Most Recent IOC", data=most_recent_ioc, pin_type="card_medium", pin_style="purple")
        if ret_val:
            phantom.save_data(pin_id_ioc_rct, pin5_name)
        
        if not pin_id_ioc_type:
            ret_val, message, pin_id_ioc_type = phantom.pin(container=container, message="IOC Types", data=", ".join(ioc_types))
        else:
            ret_val, message = phantom.update_pin(pin_id_ioc_type, message="IOC Types", data=", ".join(ioc_types))
        if ret_val:
            phantom.save_data(pin_id_ioc_type, pin6_name)
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return