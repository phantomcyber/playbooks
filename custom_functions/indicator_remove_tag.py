def indicator_remove_tag(indicator=None, tags=None, **kwargs):
    """
    Remove tag(s) from an existing indicator record.
    
    Args:
        indicator (CEF type: *): Specifies the indicator which the tag will be removed from. Supports a string indicator value or an indicator id.
        tags (CEF type: *): Comma separated list of tags. Tags should only contain characters Aa-Zz, 0-9, '-', and '_'.
    
    Returns a JSON-serializable object that implements the configured data paths:
        indicator_id: The indicator id that was changed.
        indicator_tags: The remaining tags on the indicator after the modification.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import string
    
    outputs = {}
    
    # remove whitespace from tags and convert to a list
    tags = tags.replace(' ','').split(',')
    allowed_characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + '_' + '-'
    for tag in tags:
        if any(c not in allowed_characters for c in tag):
            raise ValueError("Tags should only contain characters Aa-Zz, 0-9, '-', and '_'")

    
    url = phantom.build_phantom_rest_url('indicator')
    
    # if indicator is an int, treat it as an indicator id
    if isinstance(indicator, int):
        indicator_id = indicator
        url += f'/{indicator_id}'
        response = phantom.requests.get(url, verify=False).json()
        if response.get('id'):
            existing_tags = response['tags']
        else:
            raise RuntimeError(f"No indicator record found for indicator with id: {indicator}")

    # attempt to translate indicator string value to a indicator id
    elif isinstance(indicator, str):
        params = {'_filter_value__iexact': f'"{indicator}"'}
        response = phantom.requests.get(url, params=params, verify=False).json()
        if response['count'] == 1:
            indicator_id = response['data'][0]['id']
            url += f'/{indicator_id}'
            existing_tags = response['data'][0]['tags']
        elif response['count'] > 1:
            raise RuntimeError("Located more than 1 indicator record")
        else:
            raise RuntimeError(f"Unable to locate any indicator record for value: {indicator}")
    else:
        raise ValueError("Indicator must be a string or integer")

    new_tags = [item for item in existing_tags if item not in tags]
    data = {"tags": new_tags}
    response = phantom.requests.post(url, json=data, verify=False).json()
    if response.get('success'):
        outputs = {'indicator_id': indicator_id, 'indicator_tags': new_tags}
    else:
        raise RuntimeError(f"Failed to update tags for indicator with id: {indicator_id}")

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
