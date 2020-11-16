def format_custom_list(list_name_or_num=None, **kwargs):
    """
    Format custom list to be used in a PB.
    
    Args:
        list_name_or_num: Custom List Name or ID number
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item_0
        *.item_1
        *.item_2
        *.item_3
        *.item_4
        *.item_5
        *.item_6
        *.item_7
        *.item_8
        *.item_9
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    if not list_name_or_num:
        raise ValueError('list_name_or_num parameter is required')
    
    outputs = []
    
    # Use REST to get the custom list
    custom_list_request = phantom.requests.get(
        phantom.build_phantom_rest_url('decided_list', list_name_or_num),
        verify=False
    )
    
    # Raise error if unsuccessful
    custom_list_request.raise_for_status()
    
    # Get the list content
    custom_list = custom_list_request.json().get('content', [])
    
    # Iterate through all rows and save to a list of dicts
    for row_num, row in enumerate(custom_list):
        row_dict = {'item_{}'.format(col): val for col, val in enumerate(row)}
        row_dict['row_num'] = row_num
        outputs.append(row_dict)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
