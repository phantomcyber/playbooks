def string_md5_hash(input_string=None, **kwargs):
    """
    Hashes a text string using MD5.
    
    Args:
        input_string: The string to compute the MD5 hash on
    
    Returns a JSON-serializable object that implements the configured data paths:
        hashed_string: The input_string hashed with the MD5 algorithm
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import hashlib
    try:
        hashed_string = hashlib.md5(input_string.encode("utf-8")).hexdigest()
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"hashed_string": hashed_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
