def find_related_containers(value_list=None, minimum_match_count=None, filter_out_status=None, container=None, **kwargs):
    """
    Takes a provided list of indicator values to search for and finds all related containers. It will produce a list of the related container details.
    
    Args:
        value_list (CEF type: *): An indicator value to search on, such as a file hash or IP address. To search on all indicator values in the container, use "*".
        minimum_match_count (CEF type: *): The minimum number of similar indicator records that a container must have to be considered "related." An invalid input will default to 1 with a debug message
        filter_out_status: Filters out any containers with this status
        container (CEF type: phantom container id): The container to run indicator analysis against. Supports container object or container_id. This container will also be excluded from the results for related_containers.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.container_id (CEF type: *): The unique id of the related container
        *.container_indicator_match_count: The number of indicators matched to the related container
        *.container_status: The status of the related container e.g. new, open, closed
        *.container_type: The type of the related container, e.g. default or case
        *.container_name: The name of the related container
        *.in_case: True or False if the related container is already included in a case
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    related_containers = []
    indicator_id_dictionary = {}
    container_dictionary = {}
    
    # Get indicator ids based on value_list
    def fetch_indicator_ids(value_list):
        phantom.debug("Fetching indicator IDs")
        indicator_id_list = []
        for indicator in value_list:
            url = phantom.build_phantom_rest_url() + f'indicator?_filter_value={json.dumps(indicator)}'
            response_data = phantom.requests.get(url, verify=False).json().get('data')
            if response_data:
                for item in response_data:
                    indicator_id_list.append(item['id'])
        return indicator_id_list
    
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        current_container = container['id']
    elif isinstance(container, int):
        current_container = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    if not isinstance(minimum_match_count, int):
        phantom.debug(f"Invalid type for 'minimum_match_count', {type(minimum_match_count)} - setting to 1")
        minimum_match_count = 1
        
    # If value list is equal to * then proceed to grab all indicator records for the current container
    if isinstance(value_list, list) and value_list[0] == "*":
        new_value_list = []
        url = phantom.build_phantom_rest_url('container', current_container, 'artifacts') + '?page_size=0'
        response_data = phantom.requests.get(uri=url, verify=False).json().get('data')
        if response_data:
            for data in response_data:
                for k,v in data['cef'].items():
                    if isinstance(v, list):
                        for item in v:
                            new_value_list.append(item)
                    else:
                        new_value_list.append(v)
        indicator_id_list = fetch_indicator_ids(list(set(new_value_list)))
    elif isinstance(value_list, list):
        indicator_id_list = fetch_indicator_ids(value_list)
    else:
        raise TypeError(f"Invalid input for 'value_list': {value_list}")

    # Get list of related containers
    if indicator_id_list:
        phantom.debug("Fetching common containers")
        for indicator_id in list(set(indicator_id_list)):
            url = phantom.build_phantom_rest_url() + 'indicator_common_container?indicator_ids={}'.format(indicator_id)
            response_data = phantom.requests.get(url, verify=False).json()
            
            # Populate an indicator dictionary where the original ids are the dictionary keys and the                     
            # associated continers are the values
            if response_data:
                indicator_id_dictionary[str(indicator_id)] = []
                for item in response_data:
                    indicator_id_dictionary[str(indicator_id)].append(item['container_id'])
    else:
        raise RuntimeError('Unable to fetch indicator_ids')
        
    # Iterate through the newly created indicator id dictionary and create a dictionary where 
    # the keys are related containers and the values are the associated indicator ids
    if indicator_id_dictionary:
        phantom.debug('Converting {"indicator_id": "container_id"} to {"container_id": "indicator_id"}')
        for k,v in indicator_id_dictionary.items():
            for item in v:
                if str(item) not in container_dictionary.keys():
                    container_dictionary[str(item)] = [str(k)]
                else:
                    container_dictionary[str(item)].append(str(k))
    else:
        raise RuntimeError('Unable to create indicator_id_dictionary')
        
    # Iterate through the newly created container dictionary                
    if container_dictionary:
        
        container_number = 0
        # Dedupe the number of indicators
        for k,v in container_dictionary.items():
            container_dictionary[str(k)] = list(set(v))
             # Count how many containers are actually going to be queried based on minimum_match_count
            if len(container_dictionary[str(k)]) >= minimum_match_count:
                container_number += 1
                
        # If the container number is greater than 600, then its faster to grab all containers
        if container_number >= 600:
            phantom.debug("Number of related containers > 100. Fetching all container data")
            # Convert status to id
            status_id = None
            if isinstance(filter_out_status, str):
                url = phantom.build_phantom_rest_url('container_status') + f'?_filter_name="{filter_out_status}"'
                response = phantom.requests.get(uri=url, verify=False).json()
                if response['count'] > 0:
                    status_id = response['data'][0]['id']
            elif isinstance(filter_out_status, int):
                status_id = filter_out_status

            # Gather container data
            url = phantom.build_phantom_rest_url('container') + '?page_size=0'
            if status_id:
                url +=  f'&_exclude_status_id={status_id}'
            containers_response = phantom.requests.get(uri=url, verify=False).json()
            all_container_dictionary = {}
            if containers_response['count'] > 0:
                # Build repository of available container data
                for data in containers_response['data']:
                    all_container_dictionary[str(data['id'])] = data

                for k,v in container_dictionary.items():

                    # If any of the containers contain more than the minimum match count request that container detail.
                    if len(container_dictionary[str(k)]) >= minimum_match_count:

                        # Grab container details if its a valid container based on previous filtering.
                        if str(k) in all_container_dictionary.keys():
                            container_data = all_container_dictionary[str(k)]
                            status = container_data['status']
                            container_type = container_data['container_type']
                            container_name = container_data['name']
                            in_case = container_data['in_case']

                            # Build final output
                            outputs.append({'container_id': str(k),
                                            'container_indicator_match_count': len(container_dictionary[str(k)]),
                                            'container_status': status,
                                            'container_type': container_type,
                                            'container_name': container_name,
                                            'in_case': in_case})
            else:
                raise RuntimeError(f"'Unable to find any valid containers at url: '{url}'")
        elif container_number < 600 and container_number > 0:
            phantom.debug("Fetching related container data")
            # if the container number is smaller than 600, its faster to grab each container individiually
            for k,v in container_dictionary.items():
                # Dedupe the number of indicators
                container_dictionary[str(k)] = list(set(v))

                # If any of the containers contain more than the minimum match count request that container detail.
                if len(container_dictionary[str(k)]) >= minimum_match_count:

                    # Grab container details
                    url = phantom.build_phantom_rest_url('container', k)
                    response_data = phantom.requests.get(url, verify=False).json()
                    status = response_data['status']
                    container_type = response_data['container_type']
                    container_name = response_data['name']
                    in_case = response_data['in_case']

                    # Build final output
                    if status != filter_out_status and str(k) != str(current_container):
                        outputs.append({'container_id': str(k),
                                        'container_indicator_match_count': len(container_dictionary[str(k)]),
                                        'container_status': status,
                                        'container_type': container_type,
                                        'container_name': container_name,
                                        'in_case': in_case})
            

    else:
        raise RuntimeError('Unable to create container_dictionary')               
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
