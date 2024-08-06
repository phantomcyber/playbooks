"""
This workflow performs a volume snapshot operation on the set of volumes configured on the Flash Array (On-Premises Target) using the names provided as an input using the artifacts. This operation is triggered by Splunk SOAR Playbook to safeguard the volume data as a threat response, using action scripts in response to any critical alerts/events.
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
    
    get_flash_array_volumes_list(container=container)


    return

@phantom.playbook_block()
def get_flash_array_volumes_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_flash_array_volumes_list() called")

    location_formatted_string = phantom.format(
        container=container,
        template="""/api/{0}/volumes""",
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

    phantom.act("get data", parameters=parameters, name="get_flash_array_volumes_list", assets=["purearray"], callback=volumes_list)

    return

@phantom.playbook_block()
def volumes_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("volumes_list() called")

# Collect the parsed response body from the fetch_vol action
    get_flash_array_volumes_list_result_data = phantom.collect2(container=container, datapath=["get_flash_array_volumes_list:action_result.data.*.parsed_response_body.items.*.name"], action_results=results)

    volume_names = []
    if get_flash_array_volumes_list_result_data:
        try:
            for item in get_flash_array_volumes_list_result_data:
                if item[0]:  # Ensure there is a name present
                    volume_names.append(item[0])

        except Exception as e:
            phantom.error(f"Error extracting volume names: {str(e)}")

    # Join the volume names with newline characters for better readability
    formatted_volume_names = "\n".join(volume_names)

    # Debug statement to display only the formatted volume names
    phantom.debug(f"Formatted volume names:\n{formatted_volume_names}")

    # Save the extracted volume names to run data 
    volumes_list__volumes = volume_names
    phantom.save_run_data(key="volumes_list:volumes", value=json.dumps(volumes_list__volumes))
    
    volume_snapshot(container=container)

    return

@phantom.playbook_block()
def volume_snapshot(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("volume_snapshot() called")

 # Collect the volume name from the artifact
    volume_name_artifact = phantom.collect2(container=container, datapath=["artifact:*.cef.volume_name"])
    
    # Log collected artifacts for debugging
    phantom.debug(f"Collected volume name artifact: {volume_name_artifact}")

    # Concatenate the volume names into a single string
    if volume_name_artifact and volume_name_artifact[0][0]:
        volume_names = volume_name_artifact[0][0]
    else:
        volume_names = "default_volume_name"  # Provide a default volume name or handle the error

    phantom.debug(f"Using volume names: {volume_names}")

    body_formatted_string = json.dumps({
        "source_names": volume_names
    })
    
    location_formatted_string = phantom.format(
        container=container,
        template="/api/{0}/volume-snapshots",
        parameters=[
            "fetch_latest_fa_api_version:custom_function:latestvers"
        ])

    fetch_the_auth_token__x_auth_token = json.loads(_ if (_ := phantom.get_run_data(key="fetch_the_auth_token:x_auth_token")) != "" else "null")  # pylint: disable=used-before-assignment
    fetch_latest_fa_api_version__latestvers = json.loads(_ if (_ := phantom.get_run_data(key="fetch_latest_fa_api_version:latestvers")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "body": body_formatted_string,
            "headers": json.dumps({"x-auth-token": fetch_the_auth_token__x_auth_token, "Content-Type": "application/json"}),
            "location": location_formatted_string,
        })

    phantom.act("post data", parameters=parameters, name="volume_snapshot", assets=["purearray"], callback=logout_of_the_flash_array)

    return

# Add additional steps to reset or re-create the artifact before the playbook runs again
@phantom.playbook_block()
def reset_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reset_artifacts() called")
    
    # Code to reset or re-create the artifact
    # This is a placeholder and should be replaced with actual code to reset the artifact state

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