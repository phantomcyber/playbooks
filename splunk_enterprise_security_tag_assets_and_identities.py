"""
Collects possible user and system data types and checks Splunk Enterprise Security for asset and identity data. If there is a match, it will tag the indicator record with &quot;known asset&quot; or &quot;known identity.&quot;
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'collect_users' block
    collect_users(container=container)

    return

def collect_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_users() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags": None,
        "scope": "all",
        "container": id_value,
        "data_types": "user, user name, username, user_name",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/collect_by_cef_type", parameters=parameters, name="collect_users", callback=users_decision)

    return


def find_identities(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_identities() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""identity_lookup_expanded | search identity IN (\n%%\n\"{0}\"\n%%\n)\n| eval category=mvjoin(category, \"; \")""",
        parameters=[
            "dedup_users:custom_function_result.data.*.item"
        ])

    ################################################################################
    # Locate identities in Enterprise Security based on usernames in the event.
    ################################################################################

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "| inputlookup",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="find_identities", assets=["splunk"], callback=decision_4)

    return


def tag_identities(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_identities() called")

    filter_matching_identities__identities = json.loads(phantom.get_run_data(key="filter_matching_identities:identities"))

    parameters = []

    parameters.append({
        "tags": "known_identity",
        "indicator": filter_matching_identities__identities,
        "overwrite": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    for identity in filter_matching_identities__identities:
        parameters.append({
        "indicator": identity,
        "tags": "known_identity"
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_identities", callback=join_collect_hostnames)

    return


def filter_matching_identities(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_matching_identities() called")

    ################################################################################
    # Filter out the user names from "Collect Users" that do not have a matching value 
    # in "Find Identities"
    ################################################################################

    dedup_users_data = phantom.collect2(container=container, datapath=["dedup_users:custom_function_result.data.*.item"])
    find_identities_result_data = phantom.collect2(container=container, datapath=["find_identities:action_result.data.*.identity"], action_results=results)

    dedup_users_data___item = [item[0] for item in dedup_users_data]
    find_identities_result_item_0 = [item[0] for item in find_identities_result_data]

    filter_matching_identities__identities = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    filter_matching_identities__identities = []
    for user in dedup_users_data___item:
        for identity_result in find_identities_result_item_0:
            if user in identity_result:
                filter_matching_identities__identities.append(user)
    phantom.debug(f'Matching identities: {filter_matching_identities__identities}')
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="filter_matching_identities:identities", value=json.dumps(filter_matching_identities__identities))

    tag_identities(container=container)

    return


def users_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("users_decision() called")

    ################################################################################
    # Determine if any identities were found.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["collect_users:custom_function_result.data.*.artifact_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dedup_users(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_collect_hostnames(action=action, success=success, container=container, results=results, handle=handle)

    return


def join_collect_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_collect_hostnames() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_collect_hostnames_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_collect_hostnames_called", value="collect_hostnames")

    # call connected block "collect_hostnames"
    collect_hostnames(container=container, handle=handle)

    return


def collect_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_hostnames() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags": None,
        "scope": "all",
        "container": id_value,
        "data_types": "host, host name, hostname, host_name, ip",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/collect_by_cef_type", parameters=parameters, name="collect_hostnames", callback=hostnames_decision)

    return


def find_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_assets() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""asset_lookup_by_str | search asset IN (\n%%\n\"{0}\"\n%%\n)\n| eval category=mvjoin(category, \"; \")""",
        parameters=[
            "dedup_hosts:custom_function_result.data.*.item"
        ])

    ################################################################################
    # Locate assets in Enterprise Security based hostnames in the event.
    ################################################################################

    parameters = []

    if query_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": "| inputlookup",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="find_assets", assets=["splunk"], callback=decision_5)

    return


def filter_matching_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_matching_assets() called")

    ################################################################################
    # Filter out the user names from "collect hostnames" that do not have a matching 
    # value in "find assets"
    ################################################################################

    dedup_hosts_data = phantom.collect2(container=container, datapath=["dedup_hosts:custom_function_result.data.*.item"])
    find_assets_result_data = phantom.collect2(container=container, datapath=["find_assets:action_result.data.*.asset"], action_results=results)

    dedup_hosts_data___item = [item[0] for item in dedup_hosts_data]
    find_assets_result_item_0 = [item[0] for item in find_assets_result_data]

    filter_matching_assets__assets = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    filter_matching_assets__assets = []
    for asset in dedup_hosts_data___item:
        for asset_result in find_assets_result_item_0:
            if asset in asset_result:
                filter_matching_assets__assets.append(asset)
    phantom.debug(f'Matching assets: {filter_matching_assets__assets}')
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="filter_matching_assets:assets", value=json.dumps(filter_matching_assets__assets))

    tag_assets(container=container)

    return


def tag_assets(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_assets() called")

    filter_matching_assets__assets = json.loads(phantom.get_run_data(key="filter_matching_assets:assets"))

    parameters = []

    parameters.append({
        "tags": "known_asset",
        "indicator": filter_matching_assets__assets,
        "overwrite": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    for asset in filter_matching_assets__assets:
        parameters.append({
        "indicator": asset,
        "tags": "known_asset"
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_assets")

    return


def dedup_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dedup_users() called")

    collect_users_data = phantom.collect2(container=container, datapath=["collect_users:custom_function_result.data.*.artifact_value"])

    collect_users_data___artifact_value = [item[0] for item in collect_users_data]

    parameters = []

    parameters.append({
        "input_list": collect_users_data___artifact_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="dedup_users", callback=find_identities)

    return


def hostnames_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hostnames_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["collect_hostnames:custom_function_result.data.*.artifact_value", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dedup_hosts(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def dedup_hosts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dedup_hosts() called")

    collect_hostnames_data = phantom.collect2(container=container, datapath=["collect_hostnames:custom_function_result.data.*.artifact_value"])

    collect_hostnames_data___artifact_value = [item[0] for item in collect_hostnames_data]

    parameters = []

    parameters.append({
        "input_list": collect_hostnames_data___artifact_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/list_deduplicate", parameters=parameters, name="dedup_hosts", callback=find_assets)

    return


def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["find_identities:action_result.summary.total_events", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_matching_identities(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_collect_hostnames(action=action, success=success, container=container, results=results, handle=handle)

    return


def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["find_assets:action_result.summary.total_events", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_matching_assets(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return