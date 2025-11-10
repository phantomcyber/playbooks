def string_uri_encode(input_string=None, **kwargs):
    """
    Encodes a plain text string into its URI-encoded version.
    
    Args:
        input_string: The string to encode using URI encoding
    
    Returns a JSON-serializable object that implements the configured data paths:
        encoded_string: The URI encoded version of input_string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import urllib
    try:
        encoded_string = urllib.parse.quote(input_string)
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"encoded_string": encoded_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
