"""
This workflow performs a user deletion on the Flash Array (On-Premises Target) using the names provided as an input variable via Artifacts.\nThis operation can be triggered by Splunk SOAR Playbook to safeguard against multiple failed login attempts to the Flash Array
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_the_flash_array_versions' block
    list_the_flash_array_versions(container=container)

    return

@phantom.playbook_block()
def list_the_flash_array_versions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_the_flash_array_versions() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "location": "/api/api_version",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="list_the_flash_array_versions", assets=["purearray"], callback=fetch_latest_fa_api_version)

    return


@phantom.playbook_block()
def flasharray_login(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("flasharray_login() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

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
            "location": location_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="flasharray_login", assets=["purearray"], callback=fetch_the_auth_token)

    return

@phantom.playbook_block()
def fetch_latest_fa_api_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fetch_latest_fa_api_version() called")

    list_the_flash_array_versions_result_data = phantom.collect2(container=container, datapath=["list_the_flash_array_versions:action_result.data.*.parsed_response_body"], action_results=results)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    list_the_flash_array_versions_result_item_0 = [item[0] for item in list_the_flash_array_versions_result_data]

    fetch_latest_fa_api_version__latestvers = list_the_flash_array_versions_result_item_0[0]['version'][-1]

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
    
    get_flash_array_users_list(container=container)


    return

@phantom.playbook_block()
def get_flash_array_users_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_flash_array_users_list() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    location_formatted_string = phantom.format(
        container=container,
        template="""/api/{0}/admins\n""",
        parameters=[
            "fetch_latest_fa_api_version:custom_function:latestvers"
        ])

   # Get the x_auth_token from the previous code step
    x_auth_token = phantom.get_run_data(key="fetch_the_auth_token:x_auth_token")
    
    # Ensure the token is in the correct format
    x_auth_token = x_auth_token.strip('"')
    
    # Create the headers dictionary
    headers = {
        "x-auth-token": x_auth_token
    }
    
    # Debug statements to verify values
    phantom.debug(f"Formatted location string: {location_formatted_string}")
    phantom.debug(f"Auth token: {x_auth_token}")
    phantom.debug(f"Headers: {json.dumps(headers)}")

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "headers": json.dumps(headers),  # Ensure headers are passed as a JSON string
            "location": location_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="get_flash_array_users_list", assets=["purearray"], callback=extract_all_the_current_users)


    return

@phantom.playbook_block()
def extract_all_the_current_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_all_the_current_users() called")
    
     # Collect the parsed response body from the fetch_vol action
    get_flash_array_users_list_result_data = phantom.collect2(container=container, datapath=["get_flash_array_users_list:action_result.data.*.parsed_response_body.items.*.name"], action_results=results)

    user_names = []
    if get_flash_array_users_list_result_data:
        try:
            for item in get_flash_array_users_list_result_data:
                if item[0]:  # Ensure there is a name present
                    user_names.append(item[0])

        except Exception as e:
            phantom.error(f"Error extracting user names: {str(e)}")

    # Join the user names with newline characters for better readability
    formatted_user_names = "\n".join(user_names)

    # Debug statement to display only the formatted user names
    phantom.debug(f"Formatted user names:\n{formatted_user_names}")

    # Save the extracted user names to run data 
    extract_all_the_current_users__names = user_names
    phantom.save_run_data(key="extract_all_the_current_users:users_names", value=json.dumps(extract_all_the_current_users__names))
    
    delete_the_user(container=container)

    return

@phantom.playbook_block()
def delete_the_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("delete_the_user() called")

   # Collect the user name from the artifact
    user_name_artifact = phantom.collect2(container=container, datapath=["artifact:*.cef.user_name"])
    
    # Log collected artifacts for debugging
    phantom.debug(f"Collected user name artifact: {user_name_artifact}")

    # Concatenate the user names into a single string
    if user_name_artifact and user_name_artifact[0][0]:
        user_name = user_name_artifact[0][0]
    else:
        user_name = "default_user_name"  # Provide a default user name or handle the error

    phantom.debug(f"Using user name: {user_name}")

    # Retrieve the latest API version
    latestvers = phantom.get_run_data(key="fetch_latest_fa_api_version:latestvers").strip('"')
    
    # Debug the latest version value
    phantom.debug(f"Latest API version: {latestvers}")

    # Create the location string for the API call
    location_formatted_string = f"/api/{latestvers}/admins"

    # Retrieve the auth token
    x_auth_token = phantom.get_run_data(key="fetch_the_auth_token:x_auth_token").strip('"')

    # Debug the x-auth-token value
    phantom.debug(f"x-auth-token: {x_auth_token}")

    # Create the headers dictionary
    headers = {
        "x-auth-token": x_auth_token,
        "Content-Type": "application/json"
    }

    # Create the body for the delete request
    body = {
        "names": user_name
    }

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "headers": json.dumps(headers),  # Ensure headers are passed as a JSON string
            "location": location_formatted_string,
            "body": json.dumps(body)  # Add the body to the request
        })

    # Debug parameters to ensure they are correct
    phantom.debug(f"Parameters: {parameters}")

    # Perform the delete action
    phantom.act("delete data", parameters=parameters, name="delete_the_user", assets=["purearray"],callback=logout_of_the_flash_array)

    return

@phantom.playbook_block()
def logout_of_the_flash_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("logout_of_the_flash_array() called")

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
        phantom.act("post data", parameters=parameters, name="logout_of_the_flash_array", assets=["purearray"])
    else:
        phantom.error("No valid parameters found for post data action.")

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