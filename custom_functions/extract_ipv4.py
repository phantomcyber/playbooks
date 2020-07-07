def extract_ipv4(input_ip=None, **kwargs):
    """
    Takes a single input and attempts to extract IPv4 addresses from it using regex
    
    Args:
        input_ip
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.ip (CEF type: ip)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    ip_list = []
    for ip in input_ip:
        if type(ip) == list:
            for var in ip:
                ip_rex = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',var)
                for i in set(ip_rex):
                    ip_list.append(i)
        elif ip:
            ip_rex = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',ip)
            for i in set(ip_rex):
                ip_list.append(i)
                
    for ip in set(ip_list):
        outputs.append({"ip": ip})
            
    phantom.debug("Extracted ips: {}".format(outputs))
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
