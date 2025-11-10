def string_punycode_encode(input_string=None, **kwargs):
    """
    Encodes text using punycode and will return the UTF-8, punycode (raw) and punycode IDNA versions of the original input string.
    
    Args:
        input_string: The string to encode with punycode
    
    Returns a JSON-serializable object that implements the configured data paths:
        utf8_string: The utf-8 encoded string
        punycode_string: The raw (not for domains) punycode encoded string
        idna_string: The IDNA (for domains) punycode encoded string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    try:
        utf8_string = input_string.encode("unicode_escape").decode("ascii")
        punycode_string = input_string.encode("punycode").decode("ascii")
        idna_string = input_string.encode("idna").decode("ascii")
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
        
    outputs = {"utf8_string": utf8_string, "punycode_string": punycode_string, "idna_string": idna_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
