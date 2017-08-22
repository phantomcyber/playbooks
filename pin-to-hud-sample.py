"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'api_7' block
    api_7(container=container)

    # call 'pin_to_hud_6' block
    pin_to_hud_6(container=container)

    # call 'pin_to_hud_9' block
    pin_to_hud_9(container=container)

    return

def pin_to_hud_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    import random
    phantom.debug('pin_to_hud_9() called')

    # collect data for 'pin_to_hud_6' call
    dest_domain = filter(lambda x: x[0], phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain']))
    
    try:
        most_rcnt_domain = dest_domain[0][0]
    except:
        pass
    else:
        pin_id = phantom.get_data("pin3")
        if not pin_id:
            ret_val, message, pin_id = phantom.pin(container=container, message="Most Recent Domain", data=most_rcnt_domain, pin_type="card_medium", pin_style="red")
            phantom.debug("New Pin3")
        else:
            ret_val, message = phantom.update_pin(pin_id, message="Most Recent Domain", data=most_rcnt_domain, pin_type="card_medium", pin_style="red")
        if ret_val:
            phantom.save_data(pin_id, "pin3")

    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)
    return

def pin_to_hud_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    import random
    phantom.debug('pin_to_hud_6() called')

    # collect data for 'pin_to_hud_6' call
    dest_ip_artifacts = filter(lambda x: x[0], phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress']))
    sorc_ip_artifacts = filter(lambda x: x[0], phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress']))

    styles = set(["white", "red", "purple"])
    pin_id = phantom.get_data("pin1")
    
    if not pin_id:
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected IPs", data=str(len(dest_ip_artifacts) + len(sorc_ip_artifacts)), pin_type="card_medium", pin_style="white")
        phantom.debug("New Pin")
    else:
        style = random.sample(styles, 1)[0]
        phantom.debug(style)
        ret_val, message = phantom.update_pin(pin_id, message="Affected IPs", data=str(len(dest_ip_artifacts) + len(sorc_ip_artifacts)), pin_style=style)
    
    if ret_val:
        phantom.save_data(pin_id, "pin1")

    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)

    return

def api_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    import random
    phantom.debug('pin_to_hud_7() called')

    # collect data for 'pin_to_hud_6' call
    dest_username = filter(lambda x: x[0], phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName']))
    sorc_username = filter(lambda x: x[0], phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName']))

    styles = set(["white", "red", "purple"])
    pin_id = phantom.get_data("pin2")
    
    if not pin_id:
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected Users", data=str(len(dest_username) + len(sorc_username)), pin_type="card_medium", pin_style="purple")
        phantom.debug("New Pin2")
    else:
        # Delete and remake this one, for the sake of demonstration
        ret_val, message = phantom.delete_pin(pin_id)
        ret_val, message, pin_id = phantom.pin(container=container, message="Affected Users", data=str(len(dest_username) + len(sorc_username)), pin_type="card_medium", pin_style=random.sample(styles, 1)[0])
    
    if ret_val:
        phantom.save_data(pin_id, "pin2")
    # set container properties for: 
    update_data = {
    }

    phantom.update(container, update_data)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return