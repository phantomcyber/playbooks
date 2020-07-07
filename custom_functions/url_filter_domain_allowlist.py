def url_filter_domain_allowlist(url=None, domain_allowlist=None, **kwargs):
    """
    Input a list of urls and the name of a custom_list that contains safe domains. Output urls where the domain is NOT present in the custom_list. 
    
    Args:
        url (CEF type: url): Supports any URL format, including FTP, HTTP, HTTPS, SMB.
        domain_allowlist (CEF type: *): The name of a custom list that will be used as the list of domains to filter the URL against. Only the first column of the custom list will be used. Example: https://web.example.com/ will be parsed as web.example.com and matched to values inside my_custom_list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.filtered_url (CEF type: url): Only URLs that are not hosted at domains on the allow list will be returned as output.\
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import urlparse
    
    outputs = []
    custom_list = phantom.get_list(list_name=domain_allowlist)[2]
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
