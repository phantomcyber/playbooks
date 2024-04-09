def Public_Private_IP_Filter(IPv4=None, **kwargs):
    """
    Args:
        IPv4 (CEF type: ip)
    
    Returns a JSON-serializable object that implements the configured data paths:
        public_ip (CEF type: ip)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # Write your custom code here...

    def is_private_ipv4_address(ip_address):
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False  # Skip invalid addresses
        try:
            first = int(parts[0])
            second = int(parts[1])
            third = int(parts[2])
            fourth = int(parts[3])
        except ValueError:
            return False  # Skip invalid addresses
        if ip_address == '127.0.0.1':
            return False  # Skip loopback address
        elif first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
            return True  # Private address
        else:
            return False  # Public address
        
    def sort_ipv4_addresses(addresses):
        public = []
        private = []
        for address in addresses:
            if is_private_ipv4_address(address):
                private.append(address)
            else:
                public.append(address)
        public.sort()
        private.sort()
        return public, private
    
    addresses = IPv4
    public, private = sort_ipv4_addresses(addresses)
    public = str(public)
    public = public.strip('[')
    public = public.strip(']')
    public = public.strip("'")
    
    outputs = {'public_ip':public, 'private_ip':private}
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
