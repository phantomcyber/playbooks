def regex_extract_email(input_string=None, **kwargs):
    """
    Provide a string with emails in it to be extracted.
    Can be helpful with strings from the To or CC fields of an email: "<other_email@dom.ain.com>, 'Name' <e-mail@domain.com>"
    
    Args:
        input_string: String containing email address
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.email (CEF type: email): Parsed emails
    """
    ############################ Custom Code Goes Below This Line #################################

    if not input_string:
        raise ValueError('Missing input_string to process.')

    import re
    import json
    import phantom.rules as phantom
    
    phantom.debug(input_string)
    outputs = []

    email_regex = r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'

    for email in re.findall(email_regex, input_string, re.IGNORECASE):
        phantom.debug('Found email: {}'.format(email))
        outputs.append(
            {'email': email}
        )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
