def list_to_html(input_data=None, headers=None, include_index=None, **kwargs):
    """
    Convert a list of dicts OR a list of lists/tuples into an HTML <table> string
    
    Args:
        input_data: The data to convert
        headers: Optional comma separated list of column names.  Inferred from input_data if not provided.
        include_index: If True, adds a leading index column (#)
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: HTML table markup
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    from html import escape
    from typing import List, Dict, Any, Optional, Union

    def list_to_html_table(
        data: Union[List[Any], List[Dict[str, Any]]],
        headers: Optional[List[str]] = None,
        include_index: bool = False
    ) -> str:
        """
        Convert a plain list or list of dicts to an HTML table.

        Args:
            data (list): Either a list of dicts or a plain list.
            headers (list, optional): Optional list of headers.

        Returns:
            str: HTML table as a string.
        """
        if not isinstance(data, list):
            raise TypeError("input_data must be a list.")
        if not data:
            cols = ["#"] if include_index else []
            if headers:
                cols += headers
            header_html = ''.join(f"<th>{escape(str(h))}</th>" for h in cols)
            return f"<table><thead><tr>{header_html}</tr></thead><tbody></tbody></table>"

        # --- Handle list of dicts ---
        if all(isinstance(row, dict) for row in data):
            # Determine headers
            seen = []
            for row in data:
                for key in row.keys():
                    if key not in seen:
                        seen.append(key)
            headers = seen

            # Build table
            header_cells = []
            if include_index:
                header_cells.append("<th>#</th>")
            header_cells += [f"<th>{escape(str(h))}</th>" for h in headers]
            header_html = "".join(header_cells)
            
            rows_html = []
            for i, row in enumerate(data, start=1):
                row_cells = []
                if include_index:
                    row_cells.append(f"<td>{i}</td>")
                for h in headers:
                    val = row.get(h, "")
                    row_cells.append(f"<td>{escape(str(val))}</td>")
                rows_html.append("<tr>" + "".join(row_cells) + "</tr>")

            return f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(rows_html)}</tbody></table>"

        # --- Handle plain list ---     
        else:
            if headers is None:
                headers = ["Column 1"]

            header_cells = []
            if include_index:
                header_cells.append("<th>#</th>")
            header_cells += [f"<th>{escape(str(h))}</th>" for h in headers]
            header_html = "".join(header_cells)

            rows_html = []
            for i, item in enumerate(data, start=1):
                row_cells = []
                if include_index:
                    row_cells.append(f"<td>{i}</td>")
                row_cells.append(f"<td>{escape(str(item))}</td>")
                rows_html.append("<tr>" + "".join(row_cells) + "</tr>")

            return f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(rows_html)}</tbody></table>"

    
    result = list_to_html_table(input_data, headers.split(','))
    outputs = {"result": result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
