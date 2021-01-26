def url_parse(url=None, **kwargs):
    """
    Custom function implementation of urllib.parse from python3
    
    Args:
        url (CEF type: url)
    
    Returns a JSON-serializable object that implements the configured data paths:
        scheme: "http(s)"
        netloc: "www.splunk.com"
        path: "en_us/software/splunk-security-orchestration-and-automation.html"
        params
        query
        fragment
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from urllib.parse import urlparse
    
    outputs = {}
    if url:
        parsed = urlparse(url)
        outputs = {'scheme': parsed.scheme, 'netloc': parsed.netloc, 'path': parsed.path, 'params': parsed.params, 'query': parsed.query, 'fragment': parsed.fragment}
                
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
