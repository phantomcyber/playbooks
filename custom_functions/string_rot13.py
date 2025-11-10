def string_rot13(input_string=None, **kwargs):
    """
    Perform simple caesar substitution cipher which rotates alphabet characters by 13.  Because ROT13 is symmetric, it can be use both to encrypt and decrypt a string. 
    
    Args:
        input_string: The string to rotate using ROT13
    
    Returns a JSON-serializable object that implements the configured data paths:
        output_string: The rotated string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import codecs
    try:
        output_string = codecs.encode(input_string, 'rot_13')
    except TypeError:
        raise ValueError('inputString must be a string or bytes')
    
    outputs = {"output_string": output_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
