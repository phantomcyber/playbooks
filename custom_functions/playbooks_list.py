def playbooks_list(name=None, category=None, tags=None, **kwargs):
    """
    List all playbooks matching the provided name, category, and tags. If no filters are provided, list all playbooks.
    
    Args:
        name: Only return playbooks with the provided name.
        category: Only returns playbooks that match the provided category.
        tags: Only return playbooks with all the provided tags. Must be a comma-separated list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id: Playbook ID:
            e.g. 1234
        *.full_name: Playbook full name with repo, e.g.:
            local/playbook_name
        *.name: Playbook Name:
            e.g. My Playbook
        *.category: Playbook category:
            e.g. Uncategorized
        *.tags: List of tags:
            e.g. [ tag1, tag2, tag3 ]
        *.active: Playbook automation status:
            e.g. True or False
        *.disabled: Playbook enabled / disabled status:
            e.g. True or False
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    url = phantom.build_phantom_rest_url('playbook') + '?pretty&page_size=0'
    params = {}
    # Add Name
    if name:
        params['_filter_name'] = f'"{name}"'
    # Add Category
    if category:
        params['_filter_category'] = f'"{category}"'
        
    # Create list of tags and add tags minus whitespace 
    if tags:
        tags = [item.replace(' ','') for item in tags.split(',')]
        params['_filter_tags__contains'] = f'{json.dumps(tags)}'
            
    # Fetch playbook data
    response = phantom.requests.get(uri=url, params=params, verify=False).json()
    # If playbooks were found generate output
    if response['count'] > 0:
        for data in response['data']:
            outputs.append({'id': data['id'],
                            'full_name': f"{data['_pretty_scm']}/{data['name']}",
                            'name': data['name'],
                            'category': data['category'],
                            'tags': data['tags'],
                            'active': data['active'],
                            'disabled': data['disabled']
                           })
    else:
        phantom.debug("No playbook found for supplied filter")
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
