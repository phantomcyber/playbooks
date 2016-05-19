"""
This playbook runs all the isightpartners actions one by one.
Last updated by Phantom Team: May 19, 2016
"""
import phantom.rules as phantom
import json

def get_report_cb(action, success, campaign, results, handle):

    if not success:
        return

    return

def hunt_ip_cb(action, success, campaign, results, handle):

    if not success:
        return

    phantom.act('get report', parameters=[{ "id" : "15-00008606" }], assets=["isightpartners"], callback=get_report_cb)

    return

def hunt_domain_cb(action, success, campaign, results, handle):

    if not success:
        return

    phantom.act('hunt ip', parameters=[{ "ip" : "192.69.200.143" }], assets=["isightpartners"], callback=hunt_ip_cb)

    return

def hunt_file_cb(action, success, campaign, results, handle):

    if not success:
        return

    phantom.act('hunt domain', parameters=[{ "domain" : "us1s2.strangled.net" }], assets=["isightpartners"], callback=hunt_domain_cb)

    return


def on_start(campaign):

    phantom.act('hunt file', parameters=[{ "hash" : "70c447c9e71c8e6bd336670119e8df1b" }], assets=["isightpartners"], callback=hunt_file_cb)

    return

def on_finish(campaign, summary):

    phantom.debug("Summary: " + summary)

    return
