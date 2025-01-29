"""Defines utilities for multiple purposes

Like tgz files and formatting code.

"""

import base64
import json
import os
import tarfile
from io import BytesIO
from tempfile import NamedTemporaryFile

import black
import isort

_BLACK_MODE = black.Mode(line_length=120)
_ISORT_CONFIG = isort.Config(line_length=120, profile="black")


class ParsedPlaybookOrCustomFunction:
    """Common parent class for ParsedPlaybook and ParsedCustomFunction.

    Attributes:
        soar_name: Name of PB or CF.
        soar_json_code: JSON object.
        soar_python_code: Python code.
    """

    def __init__(self, soar_name: str, soar_json_code: str, soar_python_code: str):
        self.soar_name = soar_name
        self.soar_json_code = json.loads(soar_json_code)
        self.soar_python_code = soar_python_code

    @property
    def name(self) -> str:
        """Returns playbook / CF name."""
        return self.soar_name

    @name.setter
    def name(self, value: str):
        """Modifies playbook / CF name."""
        self.soar_name = value

    def get_json_code(self) -> str:
        """Returns JSON code of the custom function."""
        return json.dumps(self.soar_json_code, indent=4)

    def get_python_code(self) -> str:
        """Returns Python code of the custom function."""
        return self.soar_python_code

    @classmethod
    def from_text(cls, name_prefix: str):
        """Initializes from decompressed .py and .json files.

        The playbook / CF name is inferred from name_prefix.

        Args:
            name_prefix: Source file path name without extension.
        """

        name = os.path.basename(name_prefix)
        json_name = name_prefix + ".json"
        py_name = name_prefix + ".py"
        with open(json_name) as fj, open(py_name) as fp:
            return cls(name, fj.read(), fp.read())

    def to_text(self, name_prefix: str) -> None:
        """Saves playbook / CF to decompressed .py and .json files.

        Args:
            name_prefix: Source file path name without extension.
        """

        json_name = name_prefix + ".json"
        py_name = name_prefix + ".py"
        with open(json_name, "w") as fj, open(py_name, "w") as fp:
            fj.write(self.get_json_code())
            fp.write(self.get_python_code())

    @classmethod
    def from_tgz(cls, tgz_name: str):
        """Initializes from a compressed tgz file.

        The playbook / CF name is inferred from the content of tgz file.

        Args:
            tgz_name: Compressed file name (must end with ".tgz").
        """

        with tarfile.open(tgz_name, "r:gz") as tar:
            py_names = list(filter(lambda x: os.path.splitext(x)[1] == ".py", tar.getnames()))
            if len(py_names) != 1:
                raise ValueError("Playbook tgz file contains more than 1 .py files.")
            py_name = py_names[0]
            name_prefix = os.path.splitext(py_name)[0]
            json_name = name_prefix + ".json"
            if os.path.sep in name_prefix:
                raise ValueError("tgz file contains directory structure.")
            with tar.extractfile(json_name) as fj, tar.extractfile(py_name) as fp:
                return cls(name_prefix, fj.read().decode(), fp.read().decode())

    def to_tgz(self, tgz_name: str) -> None:
        """Saves playbook / CF to a compressed tgz file.

        Args:
            tgz_name: Compressed file name (must end with ".tgz").
        """

        with tarfile.open(tgz_name, "w:gz") as tar:
            json_name = self.name + ".json"
            py_name = self.name + ".py"
            for name, content in [(json_name, self.get_json_code()), (py_name, self.get_python_code())]:
                # https://stackoverflow.com/a/740839
                info = tarfile.TarInfo(name=name)
                f = BytesIO()
                info.size = f.write(content.encode())
                f.seek(0)
                tar.addfile(info, f)

    @classmethod
    def from_b64(cls, data: str):
        """Initializes from base64 encoding of compressed tgz file.

        The playbook / CF name is inferred from the content of tgz file.

        Args:
            data: Encoded file content.
        """

        with NamedTemporaryFile(suffix=".tgz") as tmpfile:
            with open(tmpfile.name, "wb") as f:
                f.write(base64.b64decode(data.encode()))
            return cls.from_tgz(tmpfile.name)

    def to_b64(self) -> str:
        """Saves playbook / CF to a compressed tgz file and encode using base64.

        Returns:
            Encoded file content.
        """

        with NamedTemporaryFile(suffix=".tgz") as tmpfile:
            self.to_tgz(tmpfile.name)
            with open(tmpfile.name, "rb") as f:
                return base64.b64encode(f.read()).decode()


def black_format_str(code: str, prefix: str, suffix: str) -> str:
    """Formats a code snippet using Black.

    Args:
        code: Code snippet string to be formatted.
        prefix: Placeholder code to temporarily add before code.
        suffix: Placeholder code to temporarily add after code.

    Returns:
        Formatted code snippet string.
    """
    # Empty global code block is "\n\n\n", but black will reduce it to "\n\n".
    # We hardcode a rule to reduce "\n{3,}" to "\n\n\n".
    if set(code) == {"\n"} and len(code) >= 3:
        return "\n\n\n"

    # Add new line if necessary to avoid invalid syntax after adding suffix.
    if not code.endswith("\n"):
        code += "\n"

    formatted = black.format_str(prefix + code + suffix, mode=_BLACK_MODE)

    assert formatted.startswith(prefix)
    assert formatted.endswith(suffix)
    return formatted[len(prefix) : len(formatted) - len(suffix)]


def isort_format_str(code: str, prefix: str, suffix: str) -> str:
    """Formats a code snippet using isort.

    Args:
        code: Code snippet string to be formatted.
        prefix: Placeholder code to temporarily add before code.
        suffix: Placeholder code to temporarily add after code.

    Returns:
        Formatted code snippet string.
    """
    # Add new line if necessary to avoid invalid syntax after adding suffix.
    if not code.endswith("\n"):
        suffix = "\n" + suffix

    formatted = isort.api.sort_code_string(prefix + code + suffix, config=_ISORT_CONFIG)

    assert formatted.startswith(prefix)
    assert formatted.endswith(suffix)
    return formatted[len(prefix) : len(formatted) - len(suffix)]


def black_isort_format_str(code: str, prefix: str, suffix: str) -> str:
    """Calls black_format_str and isort_format_str."""

    tmp = black_format_str(code, prefix, suffix)
    return isort_format_str(tmp, prefix, suffix)
