def regex_extract_ipv6(input_string=None, **kwargs):
    """
    Takes a single input and extracts all IPv6 addresses from it using regex.
    
    Args:
        input_string: An input string that may contain an arbitrary number of ipv6 addresses
    
    Returns a JSON-serializable object that implements the configured data paths:
        extracted_ipv6: Extracted ipv6 address(es). Will be none if no IP was extracted.
        input_value: The value that was used as input to produce the extracted IP(s).
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    import re
    import ipaddress
    from typing import List

    # Regex that matches IPv6 addresses, optionally bracketed, with optional zone id and CIDR
    _ipv6_like_re = re.compile(r'''
    (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\d+|\/\d+|)
    ''', re.VERBOSE)

    def extract_ipv6_addresses(text: str) -> List[str]:
        """Return a list of valid IPv6 addresses (without brackets) found in `text`."""
        candidates = [m.group(0) for m in _ipv6_like_re.finditer(text)]
        valid = []
        for cand in candidates:
            phantom.debug(f"cand = {cand}")
            # Strip brackets if present
            if cand.startswith("[") and cand.endswith("]"):
                cand = cand[1:-1]

            addr_part = cand
            # Handle CIDR
            if '/' in addr_part:
                base, prefix = addr_part.split('/', 1)
                addr_only = base
            else:
                addr_only = addr_part

            # Handle zone id
            if '%' in addr_only:
                addr_only, _zone = addr_only.split('%', 1)

            try:
                ipaddress.IPv6Address(addr_only)
                phantom.debug(f"valid = {valid}")
                valid.append(cand)  # keep original (without brackets)
            except ValueError as e:
                phantom.debug(f"ValueError thrown: {e}")
                pass
        return valid

    if not isinstance(input_string, str):
        raise TypeError(f"input_string must be a string, got {type(input_string).__name__}.")
    if input_string.strip() == "":
        raise ValueError("input_string is empty.")
    
    extracted_ips = extract_ipv6_addresses(input_string)
    phantom.debug("Extracted ips: {}".format(extracted_ips))
    if extracted_ips:
        outputs = {"extracted_ipv6": extracted_ips, "input_value": input_string}
    else:
        outputs = {"extracted_ipv6": None, "input_value": input_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
