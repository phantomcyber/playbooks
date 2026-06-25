def ip_classify(ip_list=None, **kwargs):
    """
    Classifies a list of IPv4 addresses into public and private using Python's
    ipaddress module. Covers all RFC-defined non-public ranges including RFC1918
    private, loopback, link-local, CGNAT, documentation, multicast, and reserved.
    Invalid or non-IPv4 values are returned separately rather than silently dropped.

    Args:
        ip_list (CEF type: ip): A list of IPv4 addresses to classify.

    Returns a JSON-serializable object that implements the configured data paths:
        ip (CEF type: ip): The IP address.
        classification: One of 'public', 'private', or 'invalid'.
        reason: Description of the classification (e.g. 'RFC1918', 'Loopback', 'Public').
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import ipaddress
    import phantom.rules as phantom

    outputs = []

    if not ip_list:
        return outputs

    # Normalize to list
    if isinstance(ip_list, str):
        ip_list = [ip_list]

    SPECIAL_RANGES = [
        (ipaddress.ip_network('10.0.0.0/8'),          'Private (RFC1918)'),
        (ipaddress.ip_network('172.16.0.0/12'),        'Private (RFC1918)'),
        (ipaddress.ip_network('192.168.0.0/16'),       'Private (RFC1918)'),
        (ipaddress.ip_network('127.0.0.0/8'),          'Loopback (RFC1122)'),
        (ipaddress.ip_network('169.254.0.0/16'),       'Link-Local (RFC3927)'),
        (ipaddress.ip_network('100.64.0.0/10'),        'Carrier-Grade NAT (RFC6598)'),
        (ipaddress.ip_network('192.0.2.0/24'),         'Documentation (RFC5737)'),
        (ipaddress.ip_network('198.51.100.0/24'),      'Documentation (RFC5737)'),
        (ipaddress.ip_network('203.0.113.0/24'),       'Documentation (RFC5737)'),
        (ipaddress.ip_network('192.0.0.0/24'),         'IETF Protocol Assignments'),
        (ipaddress.ip_network('198.18.0.0/15'),        'Benchmarking (RFC2544)'),
        (ipaddress.ip_network('224.0.0.0/4'),          'Multicast (RFC1112)'),
        (ipaddress.ip_network('240.0.0.0/4'),          'Reserved (RFC1112)'),
        (ipaddress.ip_network('255.255.255.255/32'),   'Broadcast'),
        (ipaddress.ip_network('0.0.0.0/8'),            'This Network (RFC1122)'),
    ]

    for ip_str in ip_list:
        if not ip_str:
            continue
        ip_str = str(ip_str).strip()
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except (ipaddress.AddressValueError, ValueError):
            outputs.append({
                'ip': ip_str,
                'classification': 'invalid',
                'reason': 'Not a valid IPv4 address'
            })
            continue

        reason = 'Public'
        classification = 'public'
        for network, label in SPECIAL_RANGES:
            if addr in network:
                reason = label
                classification = 'private'
                break

        outputs.append({
            'ip': ip_str,
            'classification': classification,
            'reason': reason
        })

    phantom.debug(f"ip_classify processed {len(ip_list)} addresses: {outputs}")

    # Return a JSON-serializable object
    assert isinstance(outputs, list)
    assert json.dumps(outputs)
    return outputs
