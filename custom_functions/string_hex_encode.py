def string_hex_encode(input_string=None, **kwargs):
    """
    Encode a string into it's hexadecimal representation.
    
    Args:
        input_string: string to convert
    
    Returns a JSON-serializable object that implements the configured data paths:
        encoded_string: input_string encoded as HEX
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    if not input_string or not isinstance(input_string, str):
        raise ValueError("input_string must be a string")
        
    encoded = input_string.encode("utf-8").hex()
    outputs = {'encoded_string': encoded}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
