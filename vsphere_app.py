"""
This playbook runs all the vsphere actions one by one.
"""
import phantom.rules as phantom
import json

def list_vms_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def revert_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list vms', parameters=[{ }], assets=["vmwarevsphere"], callback=list_vms_cb)

    return

def revert_vm1_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('revert vm', parameters=[{ "snapshot" : "Pre-Infect",  "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=revert_vm_cb)

    return

def snapshot_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('revert vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=revert_vm1_cb)

    return

def start_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('snapshot vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=snapshot_vm_cb)

    return

def suspend_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('start vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=start_vm_cb)

    return

def start_vm1_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('suspend vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=suspend_vm_cb)

    return

def stop_vm_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('start vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=start_vm1_cb)

    return

def start_vm2_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('stop vm', parameters=[{ "vmx_path" : results[0]['action_results'][0]['parameter']['vmx_path'] }], assets=["vmwarevsphere"], callback=stop_vm_cb)

    return


def on_start(incident):

    phantom.act('start vm', parameters=[{ "vmx_path" : "[ha-datacenter][DAS_labesxi7_1] WXP3x86/WXP3x86.vmx" }], assets=["vmwarevsphere"], callback=start_vm2_cb)

    return

def on_finish(incident, summary):
    phantom.debug("Summary: " + summary)
    return

