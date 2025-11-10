def extract_strings_from_vault_file(container_id=None, min_length=None, include_wide=None, limit=None, file_name=None, **kwargs):
    """
    Grab a file attachment from a Splunk SOAR container using its container_id and the filename and extract human-readable strings similar to the Unix `strings` command (ASCII, and optionally UTF-16 wide strings).
    
    Args:
        container_id (CEF type: phantom container id): The container id where the file to inspect is
        min_length: Minimum length of printable characters (default=4)
        include_wide: Also extract UTF-16LE/BE "wide" strings (default: True)
        limit: If set, truncate results to first N strings (default: 10000)
        file_name (CEF type: file name): Name of the vault file
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: Dict containing the strings extracted from the vault file and other information
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...  
    import io
    import re
    import tarfile

    def _extract_ascii_strings(data: bytes, min_len: int) -> list:
        # Printable ASCII range similar to `strings` (space through tilde).
        # Include tab and common whitespace? Classic `strings` uses isprint; we'll use 0x20–0x7E.
        pattern = re.compile(rb"[ -~]{%d,}" % min_len)
        return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]

    def _extract_utf16_strings(data: bytes, min_len: int) -> list:
        # Look for UTF-16LE and UTF-16BE ranges: ASCII chars with interleaved NULs.
        # Build patterns like: (printable + \x00){min_len,} and its BE variant.
        le = re.compile((rb"(?:[ -~]\x00){%d,}" % min_len))
        be = re.compile((rb"(?:\x00[ -~]){%d,}" % min_len))
        out = []

        for m in le.finditer(data):
            # Strip NULs and decode as ASCII (safe for this subset)
            s = m.group().replace(b"\x00", b"").decode("ascii", errors="ignore")
            if s:
                out.append(s)

        for m in be.finditer(data):
            # Drop high-order NUL bytes
            s = m.group().replace(b"\x00", b"").decode("ascii", errors="ignore")
            if s:
                out.append(s)

        return out

    def get_id_and_mime_from_name(container_id=None, file_name=None):
        base_url = phantom.build_phantom_rest_url()
        resp = phantom.requests.get(f"{base_url}container/{container_id}/attachments", verify=False)
        if resp.status_code == 200:       
            phantom.debug(resp.json())
            for entry in resp.json()['data']:
                if entry['name'].casefold() == file_name.casefold():
                    return entry['id'], entry['mime_type']
        else:
            phantom.debug(f"Error fetching attachments via REST for {container_id}")
        
        return None, None
    
    def get_document_contents(container_id=None, document_id=None):
        base_url = phantom.build_phantom_rest_url()
        resp = phantom.requests.get(f"{base_url}container/{container_id}/export?file_list[]={document_id}", stream=True, verify=False)
        if resp.status_code == 200:
            # Collect bytes (stream-safe)
            buf = io.BytesIO()
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    buf.write(chunk)

            return buf.getvalue()
        else:
            phantom.debug(f"REST GET /rest/container_id/{container_id}/export returned {resp.status_code}")
            return None
        
    def extract_tgz_to_memory(tgz_data):
        """
        Extracts the contents of a TGZ archive from a bytes object into a dictionary
        where keys are filenames and values are the file contents (as bytes).

        Args:
            tgz_data (bytes): The binary content of the .tar.gz file.

        Returns:
            dict: A dictionary containing the extracted files.
                  Keys are file paths within the archive, values are their binary content.
        """
        extracted_files = {}
        # Wrap the tgz_data in a BytesIO object to simulate a file for tarfile
        tgz_buffer = io.BytesIO(tgz_data)

        with tarfile.open(fileobj=tgz_buffer, mode="r:gz") as tar:
            for member in tar.getmembers():
                phantom.debug(member)
                if member.isfile():  # Only process regular files
                    f = tar.extractfile(member)
                    if f:  # Ensure the file object exists
                        extracted_files[member.name] = f.read()
        return extracted_files
    
    def extract_strings_from_vault(container_id=None, file_name=None, min_length=4, include_wide=True, limit=None, **kwargs):
        """
        Grab a file attachment from a Splunk SOAR container using its container_id and the filename and extract human-readable strings
        similar to the Unix `strings` command (ASCII, and optionally UTF-16 wide strings).
        """
        strings_ascii = []
        strings_wide = []
        file_bytes = None

        if not container_id:
            raise ValueError("container_id is required")

        try:
            document_id, mime_type = get_id_and_mime_from_name(container_id, file_name)
            if document_id:
                # phantom.debug(f"Found document id {document_id} for {file_name}")
                file_bytes = get_document_contents(container_id, document_id)
                if file_bytes:
                    extracted_data = extract_tgz_to_memory(file_bytes)
                    for key, value in extracted_data.items():
                        if "vault/" in key:
                            file_bytes = value
                
        except Exception as e:
            phantom.debug(f"Error while fetching attachment contents for {container_id}: {e}")

        if file_bytes is None:
            raise RuntimeError(f"Unable to retrieve attachment for container_id={container_id}")

        byte_count = len(file_bytes)

        # Extract strings
        try:
            min_len = int(min_length) if min_length is not None else 4
            if min_len < 1:
                min_len = 1
        except Exception:
            min_len = 4

        strings_ascii = _extract_ascii_strings(file_bytes, min_len)
        if include_wide:
            strings_wide = _extract_utf16_strings(file_bytes, min_len)

        # Merge results preserving order of occurrence as best we can:
        # We'll interleave by scanning once and tagging matches to avoid duplicates.
        # Simpler (and fast): concatenate and then stable-unique while preserving first occurrence.
        combined = []
        seen = set()
        for s in strings_ascii + strings_wide:
            if s not in seen:
                seen.add(s)
                combined.append(s)

        from_ascii = sum(1 for s in strings_ascii if s in seen)
        from_wide = sum(1 for s in strings_wide if s in seen)

        # Optional limit to keep playbook outputs manageable
        if limit is not None:
            try:
                n = int(limit)
                if n >= 0:
                    combined = combined[:n]
            except Exception:
                pass

        outputs = {
            "container_id": container_id,
            "strings": combined,
            "count": len(combined),
            "byte_count": byte_count,
            "from_ascii": from_ascii,
            "from_wide": from_wide if include_wide else 0,
            "filename": file_name,
            "mime_type": mime_type        
        }
        return outputs

    result = extract_strings_from_vault(container_id, file_name, min_length, include_wide, limit)
    outputs = {"result": result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
