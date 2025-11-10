def string_html_entities_encode(input_string=None, **kwargs):
    """
    Encodes a string using HTML Entities as applicable.
    
    Args:
        input_string: A string to encode using HTML entities
    
    Returns a JSON-serializable object that implements the configured data paths:
        encoded_string: The encoded version of the input_string using HTML entities
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import html
    try:
        encoded_string = html.escape(input_string)
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"encoded_string": encoded_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
