def list_demux(input_list=None, **kwargs):
    """
    Accepts a single list and converts it into multiple custom function output results. All output will be placed in the "output" datapath. Sub-items and sub-item variable names are dependent on the input.
    
    Args:
        input_list (CEF type: *): A list of objects. Nested lists are not unpacked.
    
    Returns a JSON-serializable object that implements the configured data paths:
        output (CEF type: *): Contains each item in the list.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    if isinstance(input_list, str):
        try:
            input_list = json.loads(input_list)
        except:
            raise TypeError(f"input_item expected type list but received type '{type(input_list)}'.") from None

    elif not isinstance(input_list, list):
        raise TypeError(f"input_item expected type list but received type '{type(input_list)}'")
    
    outputs = [{"output": item} for item in input_list]
    
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
