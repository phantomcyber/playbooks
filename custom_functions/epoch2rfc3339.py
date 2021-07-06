def epoch2rfc3339(_time=None, **kwargs):
    """
    convert epoch_time in seconds to rfc3339 string (YYYY-MM-DD HH:MM:SSZ)
    
    Args:
        _time (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.rfc3339timestring (CEF type: *): rfc3339 string (YYYY-MM-DD HH:MM:SSZ)
    """
    ############################ Custom Code Goes Below This Line #################################
    # Copyright (C) Endace Technology Limited, 2021 to 2021
    # SPDX-License-Identifier: Apache-2.0
    import json
    import phantom.rules as phantom
    import datetime
    outputs = []
    
    # Write your custom code here...
    outputs.append({"rfc3339timestring": datetime.datetime.utcfromtimestamp(int(_time)).isoformat()+'Z'})
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
