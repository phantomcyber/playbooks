def list_to_markdown(input_data=None, headers=None, include_index=None, **kwargs):
    """
    Convert a plain list or list of dicts to a Markdown table.
    
    Args:
        input_data: The data to convert
        headers: (Optional) Column names
        include_index: If True, adds a leading index column (#)
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: Markdown table string (header row + separator + body rows)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    from typing import Any, Dict, List, Optional, Union

    def list_or_dict_to_markdown_table(
        data: Union[List[Any], List[Dict[str, Any]], Dict[str, Any]],
        headers: Optional[List[str]] = None,
        include_index: bool = False
    ) -> str:
        """
        Convert a plain list, list of dicts, or single dict to a Markdown table.

        Rules (index column is not counted in header validation):
          • Plain list:
              - If no headers: use ['Column 1']
              - If headers provided: must be exactly length 1
          • List of dicts:
              - If no headers: infer union of keys preserving first appearance
              - If headers provided: all rows must share the same keys; headers
                must match the set of keys and have the same count (order defines display)
          • Single dict:
              - If no headers: use ['Key', 'Value']
              - If headers provided: must be exactly length 2

        Returns a Markdown table string (header row + separator + body rows).
        """

        def _md_escape(s: Any) -> str:
            # Minimal escaping to keep table structure intact
            text = "" if s is None else str(s)
            text = text.replace("|", r"\|").replace("`", r"\`").replace("\n", "<br/>")
            return text

        # ----- Single dict -----
        if isinstance(data, dict):
            if headers is not None:
                if not isinstance(headers, list) or len(headers) != 2 or any(not isinstance(h, str) for h in headers):
                    raise ValueError("For a single dict, headers must be a list of exactly two strings.")
                cols = headers
            else:
                cols = ["Key", "Value"]

            # rows: [key, value] per entry (in insertion order)
            rows = [[k, data[k]] for k in data.keys()]

            # Build table parts
            header = (["#"] if include_index else []) + cols
            sep = ["---"] * len(header)
            lines = ["| " + " | ".join(_md_escape(h) for h in header) + " |",
                     "| " + " | ".join(sep) + " |"]
            for i, (k, v) in enumerate(rows, start=1):
                row = ([i] if include_index else []) + [_md_escape(k), _md_escape(v)]
                lines.append("| " + " | ".join(map(str, row)) + " |")
            return "\n".join(lines)

        # Validate list input
        if not isinstance(data, list):
            raise TypeError("data must be a list or a dict.")

        if len(data) == 0:
            # Empty list cases
            # Plain list: if no headers, default to one column
            # Dict rows: cannot infer keys without headers
            # We'll assume plain-list semantics unless headers suggest otherwise
            if headers is None:
                cols = ["Column 1"]
            else:
                if not isinstance(headers, list) or any(not isinstance(h, str) for h in headers):
                    raise TypeError("headers must be a list of strings.")
                cols = headers

            header = (["#"] if include_index else []) + cols
            sep = ["---"] * len(header)
            return "\n".join([
                "| " + " | ".join(_md_escape(h) for h in header) + " |",
                "| " + " | ".join(sep) + " |",
            ])

        is_dict_rows = all(isinstance(r, dict) for r in data)
        is_plain_list = all(not isinstance(r, dict) for r in data)

        if not (is_dict_rows or is_plain_list):
            raise ValueError("data must be a homogeneous plain list OR a list of dicts (not mixed).")

        # ----- Plain list -----
        if is_plain_list:
            if headers is not None:
                if not isinstance(headers, list) or any(not isinstance(h, str) for h in headers):
                    raise TypeError("headers must be a list of strings.")
                if len(headers) != 1:
                    raise ValueError("For a plain list, headers must contain exactly 1 column name.")
                cols = headers
            else:
                cols = ["Column 1"]

            header = (["#"] if include_index else []) + cols
            sep = ["---"] * len(header)

            lines = [
                "| " + " | ".join(_md_escape(h) for h in header) + " |",
                "| " + " | ".join(sep) + " |"
            ]
            for i, item in enumerate(data, start=1):
                row = ([i] if include_index else []) + [_md_escape(item)]
                lines.append("| " + " | ".join(map(str, row)) + " |")
            return "\n".join(lines)

        # ----- List of dicts -----
        # Collect key sets per row
        key_sets = [set(r.keys()) for r in data]

        if headers is not None:
            if not isinstance(headers, list) or len(headers) == 0 or any(not isinstance(h, str) for h in headers):
                raise TypeError("headers must be a non-empty list of strings.")
            # Enforce consistent keys across rows
            first_keys = key_sets[0]
            for ks in key_sets[1:]:
                if ks != first_keys:
                    raise ValueError("All dict rows must have the same keys when headers are provided.")
            if len(headers) != len(first_keys):
                raise ValueError(
                    f"headers length ({len(headers)}) must match number of keys in dicts ({len(first_keys)})."
                )
            invalid = [h for h in headers if h not in first_keys]
            if invalid:
                raise ValueError(f"Header(s) not found in dict keys: {invalid}")
            cols = headers  # display order per headers
        else:
            # Infer by first appearance across rows
            seen, seen_set = [], set()
            for row in data:
                for k in row.keys():
                    if k not in seen_set:
                        seen_set.add(k)
                        seen.append(str(k))
            cols = seen

        header = (["#"] if include_index else []) + cols
        sep = ["---"] * len(header)

        lines = [
            "| " + " | ".join(_md_escape(h) for h in header) + " |",
            "| " + " | ".join(sep) + " |"
        ]
        for i, row in enumerate(data, start=1):
            values = [row.get(c, "") for c in cols]
            out = ([i] if include_index else []) + [_md_escape(v) for v in values]
            lines.append("| " + " | ".join(map(str, out)) + " |")

        return "\n".join(lines)

    result = list_or_dict_to_markdown_table(input_data, headers=headers.split(','), include_index=include_index)
    outputs = {"result": result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
