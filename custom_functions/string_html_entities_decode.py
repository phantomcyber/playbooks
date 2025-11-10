def string_html_entities_decode(input_string=None, **kwargs):
    """
    Decodes a string with HTML Entities into a plain text string.
    
    Args:
        input_string: The encoded string with HTML entities to decode
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string: The decoded plain text string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import html
    try:
        decoded_string = html.unescape(input_string)
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"decoded_string": decoded_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
