def regex_extract_url(input_string=None, **kwargs):
    """
    It takes a single input and extracts all URL matches using regex. URLs can take many forms and no regex extraction is perfect.
    
    Args:
        input_string: An input string that may contain one or more URLs.
    
    Returns a JSON-serializable object that implements the configured data paths:
        extracted_url (CEF type: url): The extracted URL. This will be None if no URL was extracted.
        input_string: The value that was used as input to produce the extracted URL.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    url_list = []
    if input_string:
        url_rex = re.findall(r'((http|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-]))', input_string)
        for url in set(url_rex):
            url_list.append(url[0])
    if url_list:
        for url in set(url_list):
            outputs.append({"extracted_url": url, "input_value": input_string})
    else:
        outputs.append({"extracted_url": None, "input_value": input_string})

    phantom.debug("Extracted urls: {}".format(outputs))
    
    
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
