"""
This playbook helps the security team detect and remove rogue wireless access points (WAPs). A Raspberry Pi 3 with a battery pack is used as a mobile scanner, periodically polling the 2.4 GHz frequency and collecting the ESSID (network name), MAC address, channel, signal strength, signal quality, and security protocol of each WAP in range. The results of each scan are compared against an allowlist of known-good network names and a potential list of potential "evil twin" network names. The results are tracked live using artifacts and Heads-up Display pins posted to the most recently created Case with the label "wireless". Finally, a team member is tasked to carry around the Raspberry Pi and use the live feed of MAC addresses and signal strengths to locate the rogue WAPs and remove them.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import re

# parse the wireless scan results returned from ssh and save the run_data with key 'parsed_access_points'
def parse_and_save_iwlist(iwlist):
    phantom.debug('parsing the iwlist data returned from the wireless scan')
    
    iwlist = iwlist[0][0]
    
    if not iwlist:
        phantom.error("no results were received from the wifi sensor")
        return
    
    if 'Scan completed' not in iwlist.split('\n')[0]:
        phantom.error("failed to parse the results of iwlist")
        return
    
    # disregard the first line
    iwlist = iwlist.split('\n', 1)[1]
    
    # split on the string that starts the results for each access point (iwlist calls them "Cells")
    access_points = re.split("          Cell ", iwlist)
    access_points = access_points[1:]
        
    # parse out the mac address, ESSID, radio frequency, signal strength, and security protocol
    for i, access_point in enumerate(access_points):
        lines = access_point.split('\n')
        access_points[i] = {}
        if re.match('\d+ - Address: ', lines[0]):
            access_points[i]['mac_address'] = lines[0].split(' - Address: ')[-1]
        else:
            phantom.error('failed to parse one of the access_points returned from iwlist')
            return
        
        for line in lines[1:]:
            if re.match('                    ESSID:"', line):
                access_points[i]['ESSID'] = line.split('ESSID:')[-1].strip('"')
            if re.match('                    Frequency:\d', line):
                access_points[i]['radio_frequency'] = line.split('Frequency:')[-1].strip()
            if re.match('                    Quality=\d', line):
                access_points[i]['signal_strength'] = line.strip()
            if re.match('                    IE: IEEE 802.11i', line):
                access_points[i]['security_protocol'] = line.split('IE:')[-1].strip()
        
        # no string matching "IEEE 802.11i" means plaintext
        if not access_points[i].get('security_protocol'):
            access_points[i]['security_protocol'] = 'plaintext'

    phantom.debug('parsed out the following wifi access points:')
    phantom.debug(access_points)
    
    phantom.save_run_data(value=json.dumps(access_points), key='parsed_access_points')
    
    return

def parse_and_save_live_case(live_case_body):
    phantom.debug('parsing the id of the live case to update')
    
    phantom.debug(live_case_body)
    
    live_case_id = live_case_body[0][0]['data'][0]['id']
    phantom.debug('tracking wireless scans in the case with id {}'.format(live_case_id))
    phantom.save_run_data(value=str(live_case_id), key='live_case_id')
    
    live_case_owner = live_case_body[0][0]['data'][0]['owner_name']
    phantom.debug('this case is owned by {}'.format(live_case_owner))
    phantom.save_run_data(value=json.dumps(live_case_owner), key='live_case_owner')
    
    return

# write a one-line comment to the activity feed
def live_comment(message):
    live_case_id = int(phantom.get_run_data(key='live_case_id'))
    phantom.comment(container=live_case_id, comment=message)
    return

def edit_distance(s1, s2):

    # ignore non-letters and upper-case vs lower-case
    s1 = s1.lower()
    s1 = re.sub(r'[^a-z]', '', s1) 
    s2 = s2.lower()
    s2 = re.sub(r'[^a-z]', '', s2) 
    
    # ignore the potential usage of some generic terms
    for generic in ['wifi', 'wireless', 'network', 'official', 'corp', 'corporate']:
        s1 = re.sub(generic, '', s1) 
        s2 = re.sub(generic, '', s2) 

    # switch the order to make sure s1 is not shorter
    if len(s1) < len(s2):
        return edit_distance(s2, s1) 

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    distances = range(len(s2) + 1)
    # iterate through each character in s1
    for i in range(len(s1)):
        next_distances = []
        next_distances.append(i + 1)
        # iterate through each character in s2
        for j in range(len(s2)):
            # insert a new character
            distance = distances[j + 1] + 1 
            # delete a character
            distance = min(distance, next_distances[j] + 1)
            # change a character
            if s1[i] != s2[j]:
                distance = min(distance, distances[j] + 1)
            # no change
            if s1[i] == s2[j]:
                distance = min(distance, distances[j])
            # keep the smallest edit
            next_distances.append(distance)

        distances = next_distances

    return next_distances[-1]

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'execute_program_1' block
    execute_program_1(container=container)

    # call 'find_case' block
    find_case(container=container)

    return

"""
Join together the execution paths of the SSH command and the HTTP query, then call utility functions in the Global Block to parse the results of each and save the necessary data using phantom.save_run_data().

If using a different version of iwlist or using a different scanning tool, the function parse_and_save_iwlist() may need to be modified.
"""
def collect_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_data() called')
    
    iwlist = phantom.collect2(container=container, datapath=['execute_program_1:action_result.data.*.output',
                                                             'execute_program_1:action_result.parameter.context.artifact_id'],
                              action_results=results)
    parse_and_save_iwlist(iwlist)
    
    live_case_body = phantom.collect2(container=container, datapath=['find_case:action_result.data.*.response_body'], action_results=results)
    parse_and_save_live_case(live_case_body)

    check_allowlist(container=container)
    
    return

def join_collect_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_collect_data() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['execute_program_1', 'find_case']):
        
        # call connected block "collect_data"
        collect_data(container=container, handle=handle)
    
    return

"""
Check the results of the WiFi scan against our allowlist of official company networks which are saved as a Custom List called "Example Company WiFi ESSID Allowlist". Stop investigating any networks that are both on the allowlist and are using WPA2.

In this case we are not pursuing further investigation of WPA2 networks that match the allowlist because our client devices will not automatically connect to them.
"""
def check_allowlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_allowlist() called')
    
    parsed_access_points = json.loads(phantom.get_run_data(key='parsed_access_points'))
    
    success, message, allowlist = phantom.get_list(list_name='Example Company WiFi ESSID Allowlist')
    
    allowlist_filtered_access_points = [
        ap for ap in parsed_access_points 
        if (
            # all ESSIDs that aren't in the allowlist are suspicious
            [ap["ESSID"]] not in allowlist
            or
            # all non-WPA2 access points are suspicious
            'WPA2' not in ap['security_protocol']
        )
    ]

    message = 'out of the {} access points identified by the scan, {} matched the allowlist and are being ignored'.format(len(parsed_access_points), len(parsed_access_points) - len(allowlist_filtered_access_points))
    phantom.debug(message)
    live_comment(message)
    
    phantom.save_run_data(value=json.dumps(allowlist_filtered_access_points), key='allowlist_filtered_access_points')
    
    check_potential_list() 
    
    return

"""
Retrieve a list of all the cards currently pinned to the Heads-up Display of the Case that will be used to track the results.
"""
def get_pins(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_pins() called')
    
    live_case = phantom.get_run_data(key='live_case_id')
    
    parameters = []
    
    # build the container_pin filter url using the live case id
    parameters.append({
        'location': "/rest/container_pin?page_size=0&_filter_container=" + live_case,
        'verify_certificate': False,
        'headers': "",
    })

    phantom.act("get data", parameters=parameters, assets=['http'], callback=update_case, name="get_pins")    
    
    return

"""
Only proceed to assign a task if the Case has no owner. This prevents duplicate task assignments while the responder is actively completing the task.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    live_case_owner = phantom.get_run_data(key='live_case_owner')
    live_case_owner = json.loads(live_case_owner)
    
    # only task a responder if there is no owner yet
    if not live_case_owner:
        find_and_disable_rogue_ap()

    return

"""
Use the HTTP app to query the REST API of this Phantom instance for the most recently created Case with the label Wireless. This is the Case that will be updated with new artifacts and Heads-up Display information containing the results of the WiFi scan.

When testing and using this playbook it may be helpful to open up this Case in Mission Control to monitor the output.
"""
def find_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('find_case() called')

    # collect data for 'find_case' call

    parameters = []
    
    # build parameters list for 'find_case' call
    parameters.append({
        'headers': "",
        'location': "rest/container?_filter_label=\"wireless\"&_filter_container_type=\"case\"&sort=start_time&order=desc&page_size=1",
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['http'], callback=join_collect_data, name="find_case")

    return

"""
Check the remaining access points against a potential list of several possible network names that an attacker might use to spoof an official company network. The potential list is loaded from the Custom List called "Potential Rogue Access Point ESSIDs". To account for small variations in network names, a Levenshtein edit distance is used so even non-exact matches will be considered suspicious.

The resulting artifact saved to the Case will have a field called "matched_rule", which will show the first entry from the Custom List that matches the given network name.
"""
def check_potential_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_potential_list() called')
    
    edit_distance_threshold = 5
    
    success, message, potentials = phantom.get_list(list_name='Potential Rogue Access Point ESSIDs')
    allowlist_filtered_access_points = json.loads(phantom.get_run_data(key='allowlist_filtered_access_points'))
    
    scanned_ESSIDs = [ap['ESSID'] for ap in allowlist_filtered_access_points]
    
    # compare each ESSID against each potential evil twin and escalate those with a sufficiently small edit distance
    matches = 0
    for ap in allowlist_filtered_access_points:
        ap['is_escalated'] = False
        ap['matched_rule'] = None
        for potential in potentials:
            if edit_distance(ap['ESSID'], potential[0]) < edit_distance_threshold:
                ap['is_escalated'] = True
                ap['matched_rule'] = potential
                matches += 1
                break

    message = '{} out of {} access points fuzzy-matched "Potential Rogue Access Point ESSIDs"'.format(
        matches, len(allowlist_filtered_access_points))
    phantom.debug(message)
    live_comment(message)

    phantom.save_run_data(value=json.dumps(allowlist_filtered_access_points), key='fuzzy_matched_access_points')

    get_pins()
    
    return

"""
Scan all WiFi access points in range of the Raspberry Pi using the command "iwlist wlan0 scanning". The following information will be returned for each access point: ESSID (network name), MAC address, channel, signal strength, signal quality, and security protocol.

If adapting to scan from a Windows machine, "netsh.exe" should be able to list access points in range.
"""
def execute_program_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('execute_program_1() called')

    # collect data for 'execute_program_1' call

    parameters = []
    
    # build parameters list for 'execute_program_1' call
    parameters.append({
        'command': "sudo /sbin/iwlist wlan0 scanning",
        'timeout': "",
        'ip_hostname': "192.168.1.100",
    })

    phantom.act(action="execute program", parameters=parameters, assets=['raspberry_pi_ssh'], callback=join_collect_data, name="execute_program_1")

    return

"""
Update the Case with artifacts and Heads-up Display cards containing the results of this playbook run. This overwrites all existing Heads-up Display cards to keep the signal strength values fresh and prevent duplicates, but the artifacts will not be deleted so they will be sortable by timestamp for a historical record.
"""
def update_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_case() called')
    
    get_pins_body = phantom.collect2(container=container, datapath=['get_pins:action_result.data.*.response_body'], action_results=results)

    # get the necessary run_data
    fuzzy_matched_access_points = json.loads(phantom.get_run_data(key='fuzzy_matched_access_points'))
    live_case_id = int(phantom.get_run_data(key='live_case_id'))

    # delete all the existing pins to prevent duplicates
    for pin in get_pins_body[0][0]['data']:
        phantom.delete_pin(int(pin['id']))
    
    # add a pin for each ap that fuzzy-matched the potential list
    for ap in fuzzy_matched_access_points:
        if ap['is_escalated']:
            phantom.pin(container=live_case_id, message=ap['signal_strength'], data=ap['mac_address'], pin_type="card_medium", pin_style="red")
            phantom.add_artifact(
                container=live_case_id,
                raw_data={},
                cef_data=ap,
                label='wireless',
                name='suspicious access point detection',
                severity='high',
                identifier=None,
                artifact_type='network')
    
    decision_1(container=container)

    return

"""
Assign a manual task for an operator to remediate. The HUD can be used to live-track the MAC addresses and signal strengths of the identified access points.
"""
def find_and_disable_rogue_ap(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('find_and_disable() called')
    
    live_case_id = phantom.get_run_data(key='live_case_id')
    
    # set user and message variables for phantom.task call
    user = "admin"
    message = "Walk around the office with the Raspberry Pi. Use the MAC addresses and signal strengths on the Heads-up Display of Case #{} to find the potential rogue access points. For each one, consider doing a packet capture to find other devices that are connecting to it. Also consider unplugging it, placing it in a faraday cage, and bringing it back to the security operations center for further forensic analysis.".format(live_case_id)

    phantom.task(user=user, message=message, respond_in_mins=30, name="find_and_disable_rogue_ap")
    
    # set the case owner to the same user
    phantom.set_owner(container=int(live_case_id), user=user)

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