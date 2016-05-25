"""Executes PagerDuty actions"""

import phantom.rules as phantom
import json

def get_oncall_cb(action, success, container, results, handle):

    if not success:
        return

    return

def list_teams_cb(action, success, container, results, handle):

    if not success:
        return

    teams = phantom.collect(results, 'action_result.data.*.name')

    phantom.debug("Teams")
    phantom.debug(teams)
    
    parameters = []
    
    for team in teams:
        parameters.append({"team": team,})

    phantom.act("get oncall", parameters=parameters, assets=["pagerduty"]) # callback=get_oncall_cb

    return


def on_start(container):

    parameters = []

    parameters.append({})

    phantom.act("list teams", parameters=parameters, assets=["pagerduty"], callback=list_teams_cb)

    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # Summary and/or action results can be collected here.

    # summary_json = phantom.get_summary()
    # summary_results = summary_json['result']
    # for result in summary_results:
            # app_runs = result['app_runs']
            # for app_run in app_runs:
                    # app_run_id = app_run['app_run_id']
                    # action_results = phantom.get_action_results(app_run_id=app_run_id)
    return
