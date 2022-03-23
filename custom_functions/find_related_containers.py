def find_related_containers(value_list=None, minimum_match_count=None, container=None, earliest_time=None, filter_status=None, filter_label=None, filter_severity=None, filter_in_case=None, **kwargs):
    """
    Takes a provided list of indicator values to search for and finds all related containers. It will produce a list of the related container details.
    
    Args:
        value_list (CEF type: *): An indicator value to search on, such as a file hash or IP address. To search on all indicator values in the container, use "*".
        minimum_match_count (CEF type: *): The minimum number of values from the value_list parameter that must match with related containers. Supports an integer or the string 'all'. Adding 'all' will set the minimum_match_count to the length of the number of unique values in the value_list. If no match count provided, this will default to 1.
        container (CEF type: phantom container id): The container to run indicator analysis against. Supports container object or container_id. This container will also be excluded from the results for related_containers.
        earliest_time: Optional modifier to only consider related containers within a time window. Default is -30d.  Supports year (y), month (m), day (d), hour (h), or minute (m)  Custom function will always set the earliest container window based on the input container "create_time".
        filter_status: Optional comma-separated list of statuses to filter on. Only containers that have statuses matching an item in this list will be included.
        filter_label: Optional comma-separated list of labels to filter on. Only containers that have labels matching an item in this list will be included.
        filter_severity: Optional comma-separated list of severities to filter on. Only containers that have severities matching an item in this list will be included.
        filter_in_case: Optional parameter to filter containers that are in a case or not.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.container_id (CEF type: *): The unique id of the related container
        *.container_indicator_match_count: The number of indicators matched to the related container
        *.container_status: The status of the related container e.g. new, open, closed
        *.container_type: The type of the related container, e.g. default or case
        *.container_name: The name of the related container
        *.in_case: True or False if the related container is already included in a case
        *.indicator_ids: Indicator ID that matched
        *.container_url (CEF type: url): Link to container
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from datetime import datetime, timedelta
    from urllib import parse
    from hashlib import sha256
    from collections import Counter
    from typing import Tuple

    outputs = []
    offset_time = None
    
    def grouper(seq, size) -> iter:
        # for iterting over a list {size} at a time
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))
    
    def get_status_ids(status_list) -> list:
        status_url = phantom.build_phantom_rest_url('container_status')
        status_url += f'?_filter_name__in={status_list}'
        status_response = phantom.requests.get(status_url, verify=False).json()
        return [item['id'] for item in status_response.get('data', [])]
        
    
    def format_offset_time(seconds) -> str:
        # Get indicator ids based on value_list
        datetime_obj = datetime.now() - timedelta(seconds=seconds)
        formatted_time = datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%fZ')  
        return formatted_time
    
    def build_outputs(container_dict, **kwargs) -> list:
        # Take container dict of id and indicators and built a list of outputs
        output_list = []
        base_url = phantom.get_base_url()     
        container_url = phantom.build_phantom_rest_url('container') + '?page_size=0'

        for k, v in kwargs.items():
            if v:
                if k == 'earliest_time':
                    container_url += f'&_filter_create_time__gt="{format_offset_time(v)}"'
                if k == 'filter_status':
                    status_list = get_status_ids(v) if all(isinstance(elem, str) for elem in v) else v
                    container_url += f'&_filter_status__in={status_list}'
                if k == 'filter_label':
                    container_url += f'&_filter_label__in={v}'
                if k == 'filter_severity':
                    container_url += f'&_filter_severity__in={v}'
                if k == 'filter_in_case':
                    container_url += f'&_filter_in_case="{v.lower()}"'
                    
                    
        container_id_list = list(container_dict.keys())
        for group in grouper(container_id_list, 100):
            query_url = container_url + f'&_filter_id__in={group}'
            container_response = phantom.requests.get(query_url, verify=False).json()
            for container_data in container_response.get('data', []):
                indicator_ids = list(container_dict[str(container_data['id'])]['indicator_ids'])
                match_count = len(indicator_ids)              
                output_list.append(
                    {
                        'container_id': container_data['id'],
                        'container_indicator_match_count': match_count,
                        'container_status': container_data['status'],
                        'container_type': container_data['container_type'],
                        'container_name': container_data['name'],
                        'container_url': base_url.rstrip('/') + f"/mission/{container_data['id']}",
                        'in_case': container_data['in_case'],
                        'indicator_ids': indicator_ids
                    }
                )
        return output_list
    
    def fetch_indicators(value_list) -> Tuple[dict, set]:
        # Creats a dictionary with the value_hash as the key with a sub dictionary of indicator ids
        indicator_dictionary = {}
        indicator_url = phantom.build_phantom_rest_url('indicator')
        hashed_list = [sha256(item.encode('utf-8')).hexdigest() for item in value_list]
        indicator_id_set = set()
        for group in grouper(hashed_list, 100):
            query_url = indicator_url + f'?_filter_value_hash__in={group}&timerange=all&page_size=0'
            indicator_response = phantom.requests.get(query_url, verify=False).json()
            for data in indicator_response.get('data', []):
                indicator_dictionary[data['value_hash']] = {'indicator_id': data['id']}
                indicator_id_set.add(data['id'])
        return indicator_dictionary, indicator_id_set
    
    def add_common_containers(indicator_dictionary) -> dict:
        # Adds container_ids to the indicator dictionary
        indicator_common_container_url = phantom.build_phantom_rest_url('indicator_common_container') + '?page_size=0'
        for indicator_hash, dict_object in indicator_dictionary.items():
            indicator_dictionary[indicator_hash].update({'container_ids': []})
            query_url = indicator_common_container_url + f"&indicator_ids={dict_object['indicator_id']}"
            container_response = phantom.requests.get(query_url, verify=False).json()
            for container_object in container_response:
                indicator_dictionary[indicator_hash]['container_ids'].append(container_object['container_id'])
        return indicator_dictionary
    
    def match_indicator_per_container(indicator_dictionary) -> dict:
        # Create a new dictionary filled with container_ids as keys and the set of related indicators as values
        container_dictionary = {}
        for dict_object in indicator_dictionary.values():
            for container_id in dict_object['container_ids']:
                if not container_dictionary.get(str(container_id)):
                    container_dictionary[str(container_id)] = {'indicator_ids': {dict_object['indicator_id']}}
                else:
                    container_dictionary[str(container_id)]['indicator_ids'].add(dict_object['indicator_id'])
        return container_dictionary
    
    def test_minimum_match(minimum_match_count, value_list) -> None:
        # Fail early if minimum_match_count excees the number of provided values
        if isinstance(minimum_match_count, int) and minimum_match_count > len(value_list):
            raise RuntimeError(
                f"The provided minimum_match_count '{minimum_match_count}' excees the number of unique values from the event - '{len(value_list)}'. "
                f"Try providing additional values in the value_list, decreasing the minimum_match_count, or entering 'all' in minimum_match_count."
            )
        return
    
    # Ensure valid time modifier
    if earliest_time:
        # convert user-provided input to seconds
        char_lookup = {'y': 31557600, 'mon': 2592000, 'w': 604800, 'd': 86400, 'h': 3600, 'm': 60}
        pattern = re.compile(r'-(\d+)([mM][oO][nN]|[yYwWdDhHmM]{1})$')
        if re.search(pattern, earliest_time):
            integer, char = (re.findall(pattern, earliest_time)[0])
            time_in_seconds = int(integer) * char_lookup[char.lower()]
        else:
            raise RuntimeError(f'earliest_time string "{earliest_time}" is incorrectly formatted. Format is -<int><time> where <int> is an integer and <time> is y, mon, w, d, h, or m. Example: "-1h"')
    else:
        # default 30 days in seconds
        time_in_seconds = 2592000

    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        current_container = container['id']
    elif isinstance(container, int):
        current_container = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    ## Start Input Checking ##
    ## -------------------- ##

    # If value list is equal to * then proceed to grab all indicator records for the current container
    if value_list and ((isinstance(value_list, list) and "*" in value_list) or (isinstance(value_list, str) and value_list == "*")):
        new_value_list = set()
        url = phantom.build_phantom_rest_url('container', current_container, 'artifacts') + '?page_size=0'
        response_data = phantom.requests.get(uri=url, verify=False).json()
        for data in response_data.get('data', []):
            for k,v in data['cef'].items():
                if isinstance(v, str) or isinstance(v, bool) or isinstance(v, int) or isinstance(v, float):
                     new_value_list.add(str(v))
        value_list = list(new_value_list)
    elif isinstance(value_list, list):
        value_set = set()
        for item in value_list:
            if isinstance(item, str) or isinstance(item, bool) or isinstance(item, int) or isinstance(item, float):
                value_set.add(str(item))
        value_list = list(value_set)
    elif isinstance(item, str) or isinstance(item, bool) or isinstance(item, int) or isinstance(item, float):
        value_list = [str(value_list)]
    else:
        raise TypeError(f"Invalid input for value_list: '{value_list}'")
    
    # check minimum_match_count is valid
    if minimum_match_count and not isinstance(minimum_match_count, int) and not isinstance(minimum_match_count, str):
        raise TypeError(f"Invalid type for 'minimum_match_count', {type(minimum_match_count)}, must be 'int' or the string 'all'")
    elif isinstance(minimum_match_count, str) and minimum_match_count.lower() == 'all':
        minimum_match_count = len(value_list)
    elif not minimum_match_count:
        minimum_match_count = 1
    test_minimum_match(minimum_match_count, value_list)
    
    # Put filters in list form
    if isinstance(filter_status, str):
        filter_status = [item.strip().lower() for item in filter_status.split(',')]
    if isinstance(filter_label, str):
        filter_label = [item.strip().lower() for item in filter_label.split(',')]
    if isinstance(filter_severity, str):
        filter_severity = [item.strip().lower() for item in filter_severity.split(',')]
    if isinstance(filter_in_case, str) and filter_in_case.lower() == 'false':
        filter_in_case = False
    
    ## ------------------- ##
    ## End Endput Checking ##


    indicator_dictionary, indicator_id_set = fetch_indicators(value_list)

    # Quit early if no indicator_ids were found
    if not indicator_dictionary:
        phantom.debug(f"No indicators IDs found for provided values: '{value_list}'")
        assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
        return outputs
    
    add_common_containers(indicator_dictionary)
    container_dict = match_indicator_per_container(indicator_dictionary)
    for container_id in list(container_dict.keys()):
        if len(container_dict[container_id]['indicator_ids'].intersection(indicator_id_set)) < minimum_match_count:
            del(container_dict[container_id])
    
    if container_dict:
        outputs = build_outputs(
            container_dict,
            earliest_time=time_in_seconds, 
            filter_status=filter_status, 
            filter_label=filter_label, 
            filter_severity=filter_severity, 
            filter_in_case=filter_in_case
        )
    else:
        phantom.debug(f"No related containers found for '{minimum_match_count}' minimum matches out of the provided values: '{value_list}'")
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
