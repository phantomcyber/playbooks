def filter_out_domain_list_from_url(url=None, custom_list_name=None, **kwargs):
    """
    Input a list of urls and the name of a custom_list that contains safe domains. Output urls where the domain is NOT present in the custom_list. Useful for ensuring that you detonate only interesting urls.
    
    Args:
        url (CEF type: url)
        custom_list_name
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.filtered_url (CEF type: url)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import urlparse
    
    outputs = []
    custom_list = phantom.get_list(list_name=custom_list_name)[2]
    custom_list = [item[0] for item in custom_list]
    for var in url:
        if var:
            parsed_url = urlparse.urlparse(var)
            if parsed_url.netloc not in custom_list:
                outputs.append({'filtered_url': var})
                
    phantom.debug("Filtered URLs: {}".format(outputs))
        
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
