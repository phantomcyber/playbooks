"""
This workflow performs a user deletion on the Flash Array (On-Premises Target) using the names provided as an input variable via Custom lists. This operation can be triggered by Splunk SOAR Playbook to safeguard against multiple failed login attempts to the Flash Array&quot;
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'useragent_setup' block
    useragent_setup(container=container)

    return

@phantom.playbook_block()
def list_the_flash_array_versions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_the_flash_array_versions() called")
    
    user_agent = json.loads(phantom.get_run_data(key="useragent_setup:user_agent"))

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "headers": json.dumps({"User-agent": user_agent}),
        "location": "/api/api_version",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="list_the_flash_array_versions", assets=["flasharray"], callback=fetch_latest_fa_api_version)

    return

@phantom.playbook_block()
def flasharray_login(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("flasharray_login() called")
    
    user_agent = json.loads(phantom.get_run_data(key="useragent_setup:user_agent"))

    location_formatted_string = phantom.format(
        container=container,
        template="""\n/api/{0}/login\n""",
        parameters=[
            "fetch_latest_fa_api_version:custom_function:latestvers"
        ])

    fetch_latest_fa_api_version__latestvers = json.loads(_ if (_ := phantom.get_run_data(key="fetch_latest_fa_api_version:latestvers")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "headers": json.dumps({"User-agent": user_agent}),
            "location": location_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="flasharray_login", assets=["flasharray"], callback=fetch_the_auth_token)


    return

@phantom.playbook_block()
def fetch_latest_fa_api_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fetch_latest_fa_api_version() called")

    list_the_flash_array_versions_result_data = phantom.collect2(container=container, datapath=["list_the_flash_array_versions:action_result.data.*.parsed_response_body"], action_results=results)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    try:
        list_the_flash_array_versions_result_item_0 = [item[0] for item in list_the_flash_array_versions_result_data if item and item[0]]
        
        if not list_the_flash_array_versions_result_item_0 or 'version' not in list_the_flash_array_versions_result_item_0[0]:
            raise ValueError("No valid version data found")

        fetch_latest_fa_api_version__latestvers = list_the_flash_array_versions_result_item_0[0]['version'][-1]

    except (IndexError, KeyError, ValueError) as e:
        phantom.error(f"Failed to fetch the latest FA API version: {str(e)}")
        return

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="fetch_latest_fa_api_version:latestvers", value=json.dumps(fetch_latest_fa_api_version__latestvers))

    flasharray_login(container=container)
    
    return

@phantom.playbook_block()
def fetch_the_auth_token(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fetch_the_auth_token() called")

    flasharray_login_result_data = phantom.collect2(container=container, datapath=["flasharray_login:action_result.data.*.response_headers.x-auth-token"], action_results=results)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    flasharray_login_result_item_0 = [item[0] for item in flasharray_login_result_data]
    phantom.debug(flasharray_login_result_data[0][0])

    fetch_the_auth_token__x_auth_token = flasharray_login_result_data[0][0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="fetch_the_auth_token:x_auth_token", value=json.dumps(fetch_the_auth_token__x_auth_token))
    
    delete_the_user(container=container)


    return

@phantom.playbook_block()
def logout_of_the_flash_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("logout_of_the_flash_array() called")
    
    user_agent = json.loads(phantom.get_run_data(key="useragent_setup:user_agent"))

     # Retrieve the latest version and x_auth_token from the run data
    fetch_latest_fa_api_version__latestvers = phantom.get_run_data(key="fetch_latest_fa_api_version:latestvers").strip('"')
    fetch_the_auth_token__x_auth_token = phantom.get_run_data(key="fetch_the_auth_token:x_auth_token").strip('"')

    # Log the retrieved values for debugging
    phantom.debug(f"Latest version: {fetch_latest_fa_api_version__latestvers}")
    phantom.debug(f"X-Auth-Token: {fetch_the_auth_token__x_auth_token}")

    # Check if the version and x_auth_token were retrieved successfully
    if not fetch_latest_fa_api_version__latestvers:
        phantom.error("Latest version not found")
        return
    if not fetch_the_auth_token__x_auth_token:
        phantom.error("X-Auth-Token not found")
        return

    # Format the location string using the latest version
    location_formatted_string = f"/api/{fetch_latest_fa_api_version__latestvers}/logout"

    # Prepare headers as a dictionary
    headers = {
        "X-Auth-Token": fetch_the_auth_token__x_auth_token,
        "User-Agent"  : user_agent,
        "Content-Type": "application/json"
    }

    # Prepare the parameters for the post data action
    parameters = [{
        "location": location_formatted_string,
        "headers": json.dumps(headers)  # Convert headers to JSON string
    }]

    # Debug the prepared parameters
    phantom.debug(f"parameters: {parameters}")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # Perform the post data action with the prepared parameters
    if parameters:
        phantom.act("post data", parameters=parameters, name="logout_of_the_flash_array", assets=["flasharray"])
    else:
        phantom.error("No valid parameters found for post data action.")

    return

@phantom.playbook_block()
def useragent_setup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("useragent_setup() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    import platform
    USER_AGENT_BASE = 'Pure-Storage-Splunk-SOAR-Integration'
    VERSION = 'v1.0'
    user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": USER_AGENT_BASE,
            "class": __name__,
            "version": VERSION,
            "platform": platform.platform(),
        }

    phantom.save_run_data(key="useragent_setup:user_agent", value=json.dumps(user_agent))

    ################################################################################
    ## Custom Code End
    ################################################################################
    list_the_flash_array_versions(container=container)

    return

@phantom.playbook_block()
def delete_the_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_the_user() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    user_agent = json.loads(phantom.get_run_data(key="useragent_setup:user_agent"))
    # Collect the volume name from the artifact
    #volume_name_artifact = phantom.collect2(container=container, datapath=["artifact:*.cef.volume_name"])
    
    # Log collected artifacts for debugging
    #phantom.debug(f"Collected volume name artifact: {volume_name_artifact}")

    # Concatenate the volume names into a single string
    users_names_list = phantom.get_list(list_name="pure_flasharray_users")[2][0]

    
    if isinstance(users_names_list, list):
        users_names = ', '.join(users_names_list)
    else:
        users_names = users_names_list

    # Format the body of the POST request
    body_formatted_string = json.dumps({
        "names": users_names
    })
    
    fetch_the_auth_token__x_auth_token = json.loads(_ if (_ := phantom.get_run_data(key="fetch_the_auth_token:x_auth_token")) != "" else "null")  # pylint: disable=used-before-assignment
    fetch_latest_fa_api_version__latestvers = json.loads(_ if (_ := phantom.get_run_data(key="fetch_latest_fa_api_version:latestvers")) != "" else "null")
    
    location_formatted_string = phantom.format(
        container=container,
        template="/api/{0}/admins",
        parameters=[
            "fetch_latest_fa_api_version:custom_function:latestvers"
        ])

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "body": body_formatted_string,
            "headers": json.dumps({"x-auth-token": fetch_the_auth_token__x_auth_token, "Content-Type": "application/json","User-agent": user_agent}),
            "location": location_formatted_string,
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("delete data", parameters=parameters, name="delete_the_user", assets=["flasharray"], callback=logout_of_the_flash_array)

    return

@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return