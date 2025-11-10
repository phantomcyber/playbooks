def string_analyze_cidr(input_cidr=None, **kwargs):
    """
    Validate and analyze an IPv4 CIDR (e.g., '192.168.1.0/24').
    
        Returns a dict with:
          - network: '192.168.1.0/24'
          - network_address: '192.168.1.0'
          - prefix_length: 24
          - subnet_mask: '255.255.255.0'
          - total_ips: 256
          - usable_hosts: 254
          - host_range: ('192.168.1.1', '192.168.1.254')
          - network_size: 'smaller (more hosts)' / 'larger (fewer hosts)' style hint
          - scope: classification string (e.g., 'Private (RFC1918)', 'Documentation (RFC5737)', 'Public/Globally Routable', etc.)
    
    Args:
        input_cidr: IPv4 CIDR (e.g., 192.168.1.0/24)
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: A dict with:
                  - network: '192.168.1.0/24'
                  - network_address: '192.168.1.0'
                  - prefix_length: 24
                  - subnet_mask: '255.255.255.0'
                  - total_ips: 256
                  - usable_hosts: 254
                  - host_range: ('192.168.1.1', '192.168.1.254')
                  - network_size: 'smaller (more hosts)' / 'larger (fewer hosts)' style hint
                  - scope: classification string (e.g., 'Private (RFC1918)', 'Documentation (RFC5737)', 'Public/Globally Routable', etc.)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    from ipaddress import ip_network, IPv4Network

    def analyze_cidr(cidr: str) -> dict:
        """
        Validate and analyze an IPv4 CIDR (e.g., '192.168.1.0/24').

        Returns a dict with:
          - network: '192.168.1.0/24'
          - network_address: '192.168.1.0'
          - prefix_length: 24
          - subnet_mask: '255.255.255.0'
          - total_ips: 256
          - usable_hosts: 254
          - host_range: ('192.168.1.1', '192.168.1.254')
          - network_size: 'smaller (more hosts)' / 'larger (fewer hosts)' style hint
          - scope: classification string (e.g., 'Private (RFC1918)', 'Documentation (RFC5737)', 'Public/Globally Routable', etc.)
        Raises: ValueError if cidr is invalid or not IPv4.
        """
        try:
            net = ip_network(cidr, strict=False)
        except Exception as e:
            raise ValueError(f"Invalid CIDR: {cidr!r} ({e})")
        if not isinstance(net, IPv4Network):
            raise ValueError("Only IPv4 CIDRs are supported.")

        # Basic pieces
        network = str(net)
        network_address = str(net.network_address)
        prefix_length = net.prefixlen
        subnet_mask = str(net.netmask)
        total_ips = net.num_addresses

        # Usable host logic with proper handling for /31 and /32
        if prefix_length == 31:
            # RFC 3021: both addresses usable on point-to-point links
            usable_hosts = 2
            first_usable = str(net.network_address)
            last_usable = str(net.broadcast_address)
        elif prefix_length == 32:
            # Single host route
            usable_hosts = 1
            first_usable = last_usable = str(net.network_address)
        else:
            usable_hosts = max(total_ips - 2, 0)
            first_usable = str(net.network_address + 1) if usable_hosts > 0 else None
            last_usable = str(net.broadcast_address - 1) if usable_hosts > 0 else None

        # Human-ish size hint (lower prefix = bigger network)
        if prefix_length <= 16:
            network_size = "large (more hosts)"
        elif prefix_length <= 24:
            network_size = "medium"
        else:
            network_size = "small (fewer hosts)"

        # Scope / hierarchical location classification
        specials = [
            ("Private (RFC1918)", [ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16")]),
            ("Carrier-Grade NAT (RFC6598)", [ip_network("100.64.0.0/10")]),
            ("Loopback", [ip_network("127.0.0.0/8")]),
            ("Link-Local (APIPA)", [ip_network("169.254.0.0/16")]),
            ("Documentation (RFC5737)", [ip_network("192.0.2.0/24"), ip_network("198.51.100.0/24"), ip_network("203.0.113.0/24")]),
            ("Benchmarking (RFC2544/RFC6890)", [ip_network("198.18.0.0/15")]),
            ("IETF Protocol Assignments", [ip_network("192.0.0.0/24")]),
            ("Multicast", [ip_network("224.0.0.0/4")]),
            ("Reserved (Future Use)", [ip_network("240.0.0.0/4")]),
            ("Limited Broadcast", [ip_network("255.255.255.255/32")]),
        ]

        scope = "Public/Globally Routable"
        for label, blocks in specials:
            if any(net.subnet_of(b) or b.subnet_of(net) or net.overlaps(b) for b in blocks):
                scope = label
                break
        # Tighten “Private” if it's exactly RFC1918; otherwise, ipaddress.is_private covers more than RFC1918.
        if scope == "Public/Globally Routable" and net.is_private:
            scope = "Private/Non-Global"

        return {
            "network": network,
            "network_address": network_address,
            "prefix_length": prefix_length,
            "subnet_mask": subnet_mask,
            "total_ips": total_ips,
            "usable_hosts": usable_hosts,
            "host_range": (first_usable, last_usable),
            "network_size": network_size,
            "scope": scope,
        }

    outputs = {"result" : analyze_cidr(input_cidr)}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
