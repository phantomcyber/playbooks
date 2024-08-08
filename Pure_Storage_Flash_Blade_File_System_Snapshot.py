"""
This workflow performs a File System snapshot operation on the set of File Systems configured on the Flash Blade (On-Premises Target) using the names provided as an input using the artifacts. This operation is triggered by Splunk SOAR Playbook to safeguard the File System data as a threat response, using action scripts in response to any critical alerts/events.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'list_the_flash_blade_versions' block
    list_the_flash_blade_versions(container=container)

    return

@phantom.playbook_block()
def flashblade_login(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("flashblade_login() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "location": "/api/login",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="flashblade_login", assets=["flashblade"], callback=fetch_the_auth_token)

    return


@phantom.playbook_block()
def fetch_the_auth_token(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fetch_the_auth_token() called")

    flashblade_login_result_data = phantom.collect2(container=container, datapath=["flashblade_login:action_result.data.*.response_headers"], action_results=results)

    # Debug the collected data
    phantom.debug(f"flashblade_login_result_data: {flashblade_login_result_data}")

    if flashblade_login_result_data:
        flashblade_login_result_item_0 = [item[0] for item in flashblade_login_result_data if item[0]]
        phantom.debug(f"flashblade_login_result_item_0: {flashblade_login_result_item_0}")

        if flashblade_login_result_item_0:
            response_headers = flashblade_login_result_item_0[0]
            phantom.debug(f"Response Headers: {response_headers}")

            # Normalize header keys to lowercase
            normalized_headers = {key.lower(): value for key, value in response_headers.items()}
            phantom.debug(f"Normalized Response Headers: {normalized_headers}")

            # Extract x-auth-token from the normalized response headers
            fetch_the_auth_token__x_auth_token = normalized_headers.get('x-auth-token')
            phantom.debug(f"Auth token: {fetch_the_auth_token__x_auth_token}")

            if fetch_the_auth_token__x_auth_token:
                # Save the extracted auth token to run data
                phantom.save_run_data(key="fetch_the_auth_token:x_auth_token", value=json.dumps(fetch_the_auth_token__x_auth_token))
                
                list_the_file_systems(container=container)
                
            else:
                phantom.error("x-auth-token not found in the response headers.")
        else:
            phantom.error("No auth token found in the response headers.")
    else:
        phantom.error("No data collected from the response headers.")
    
    return

@phantom.playbook_block()
def list_the_flash_blade_versions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_the_flash_blade_versions() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "headers": "",
        "location": "/api/api_version",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="list_the_flash_blade_versions", assets=["flashblade"], callback=fetch_latest_fb_api_version)

    return


@phantom.playbook_block()
def fetch_latest_fb_api_version(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("fetch_latest_fb_api_version() called")
    list_the_flash_blade_versions_result_data = phantom.collect2(container=container, datapath=["list_the_flash_blade_versions:action_result.data.*.parsed_response_body"], action_results=results)

    if not list_the_flash_blade_versions_result_data:
        phantom.error("Failed to fetch versions data.")
        return

    list_the_flash_blade_versions_result_item_0 = [item[0] for item in list_the_flash_blade_versions_result_data if item[0]]
    phantom.debug(f"Versions Data: {list_the_flash_blade_versions_result_item_0}")

    if list_the_flash_blade_versions_result_item_0 and 'versions' in list_the_flash_blade_versions_result_item_0[0]:
        latest_version = list_the_flash_blade_versions_result_item_0[0]['versions'][-1]
    else:
        phantom.error("Failed to retrieve versions from response.")
        return

    phantom.debug(f"Latest version: {latest_version}")

    phantom.save_run_data(key="fetch_latest_fb_api_version:version", value=json.dumps(latest_version))

    flashblade_login(container=container)

    return

@phantom.playbook_block()
def list_the_file_systems(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_the_file_systems() called")



 # Collect the volume name from the artifact
    filesystem_name_artifact = phantom.collect2(container=container, datapath=["artifact:*.cef.filesystem_name"])
    
    # Log collected artifacts for debugging
    phantom.debug(f"Collected filesyste name artifact: {filesystem_name_artifact}")

        

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # Concatenate the filesystem names into a single list
    if filesystem_name_artifact and filesystem_name_artifact[0][0]:
        filesystem_names = filesystem_name_artifact[0][0].split(',')
    else:
        filesystem_names = ["default_filesystem_name"]  # Provide a default filesystem name or handle the error

    phantom.debug(f"Using filesystem names: {filesystem_names}")

    body_formatted_string = json.dumps({
        "source_names": filesystem_names
    })
    
    location_formatted_string = phantom.format(
        container=container,
        template="""/api/{0}/file-systems\n""",
        parameters=[
            "fetch_latest_fb_api_version:custom_function:version"
        ])

    fetch_the_auth_token__x_auth_token = json.loads(_ if (_ := phantom.get_run_data(key="fetch_the_auth_token:x_auth_token")) != "" else "null")  # pylint: disable=used-before-assignment
    fetch_latest_fb_api_version__version = json.loads(_ if (_ := phantom.get_run_data(key="fetch_latest_fb_api_version:version")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if location_formatted_string is not None:
        parameters.append({
            "headers": json.dumps({"x-auth-token": fetch_the_auth_token__x_auth_token, "Content-Type": "application/json"}),
            "location": location_formatted_string,
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="list_the_file_systems", assets=["flashblade"], callback=extract_the_filesystems)

    return

@phantom.playbook_block()
def extract_the_filesystems(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_the_filesystems() called")

    list_the_file_systems_result_data = phantom.collect2(container=container, datapath=["list_the_file_systems:action_result.data.*.parsed_response_body.items.*.name"], action_results=results)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(f"output --->{list_the_file_systems_result_data}")
    list_the_file_systems_result_item_0 = [item[0] for item in list_the_file_systems_result_data]

    extract_the_filesystems__filesystem_names = None

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="extract_the_filesystems:filesystem_names", value=json.dumps(extract_the_filesystems__filesystem_names))

    filesystem_snapshot(container=container)

    return

@phantom.playbook_block()
def filesystem_snapshot(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filesystem_snapshot() called")
    
    
    
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # Collect the FIlesystem name from the artifact
    filesystem_name_artifact = phantom.collect2(container=container, datapath=["artifact:*.cef.filesystem_name"])
    
    
    # Log collected artifacts for debugging
    phantom.debug(f"Collected filesystem name artifact: {filesystem_name_artifact}")

        
        # Concatenate the filesystem names into a single list
    if filesystem_name_artifact:
        filesystem_names = filesystem_name_artifact[0][0]
    else:
        filesystem_names = ["default_filesystem_name"]  # Provide a default filesystem name or handle the error

    phantom.debug(f"Using filesystem names: {filesystem_names}")
    
    #body_formatted_string = json.dumps({
    #    "sources": filesystem_names,
    #    "suffix": "test"
    #})
    body_formatted_string = json.dumps({
        "source_names": filesystem_names
    })
    fetch_the_auth_token__x_auth_token = json.loads(_ if (_ := phantom.get_run_data(key="fetch_the_auth_token:x_auth_token")) != "" else "null") # pylint: disable=used-before-assignment
    vers = json.loads(phantom.get_run_data(key="fetch_latest_fb_api_version:version"))
    for filesystem_name in filesystem_names.split(','):
        
        location_formatted_string = phantom.format(
            container=container,
            template=f"/api/{vers}/file-system-snapshots?source_names={filesystem_name}",
            #parameters=[
            #    "fetch_latest_fb_api_version:custom_function:version"
            #]
            )

        parameters = []

        if location_formatted_string is not None:
            parameters.append({
                #"body": body_formatted_string,
                "headers": json.dumps({"x-auth-token": fetch_the_auth_token__x_auth_token, "Content-Type": "application/json"}),
                "location": location_formatted_string
            })


    ################################################################################
    ## Custom Code End
    ################################################################################

        phantom.act("post data", parameters=parameters, name="filesystem_snapshot", assets=["flashblade"], callback=logout_of_the_flash_blade)
    
    return

@phantom.playbook_block()
def logout_of_the_flash_blade(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("logout_of_the_flash_blade() called")


    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # Retrieve the latest x_auth_token from the run data
    fetch_the_auth_token__x_auth_token = phantom.get_run_data(key="fetch_the_auth_token:x_auth_token").strip('"')

    # Log the retrieved values for debugging
    phantom.debug(f"X-Auth-Token: {fetch_the_auth_token__x_auth_token}")

    # Check if the version and x_auth_token were retrieved successfully
    if not fetch_the_auth_token__x_auth_token:
        phantom.error("X-Auth-Token not found")
        return

    # Format the location string using the latest version
    location_formatted_string = f"/api/logout"

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
    ## Custom Code End
    ################################################################################

    # Perform the post data action with the prepared parameters
    if parameters:
        phantom.act("post data", parameters=parameters, name="logout_of_the_flash_blade", assets=["flashblade"])
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