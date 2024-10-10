def generate_random_password(password_length=None, **kwargs):
    """
    Args:
        password_length: Length for the randomly generated password
    
    Returns a JSON-serializable object that implements the configured data paths:
        password (CEF type: password)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import random
    import string

    outputs = {}
    password = ""
    
    if password_length:
        password_length = password_length
    else:
        password_length = 12
    
    random_source = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    for i in range(password_length):
        password += random.choice(random_source)

    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)
    outputs['password'] = password
    phantom.debug(f"Randomly Generated Password: {password}")
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
