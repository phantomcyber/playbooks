import json
import logging
import re
from dataclasses import dataclass
from typing import Optional, Union

from .utils import ParsedPlaybookOrCustomFunction, black_isort_format_str

logger = logging.getLogger(__name__)

# String that denotes start of a new playbook function.
# Old playbooks may not have "@phantom.playbook_block()" decorator, such as "tvm-main/[TVM] SLA Notification.py".
_FUNC_HEADER_REGEX = r"(?:\n@phantom\.playbook_block\(\))?\ndef "

# Playbook comments that denote start and end of global / local custom code.
_GLOBAL_SEP = "#" * 80
_GLOBAL_START = f"\n{_GLOBAL_SEP}\n## Global Custom Code Start\n{_GLOBAL_SEP}\n"
_GLOBAL_END = f"{_GLOBAL_SEP}\n## Global Custom Code End\n{_GLOBAL_SEP}\n"
_LOCAL_SEP = "    " + "#" * 80
_LOCAL_START = f"\n{_LOCAL_SEP}\n    ## Custom Code Start\n{_LOCAL_SEP}\n"
_LOCAL_END = f"{_LOCAL_SEP}\n    ## Custom Code End\n{_LOCAL_SEP}\n"


@dataclass
class _GlobalCode:
    """Parsed global code at start of playbook."""

    # String before custom code.
    pre_code: str
    # Custom code content, None for no custom code.
    custom_code: Optional[str]
    # String after custom code. Empty string if no custom code.
    post_code: str

    def __str__(self):
        ans = self.pre_code
        if self.custom_code is not None:
            ans += _GLOBAL_START + self.custom_code + _GLOBAL_END
        ans += self.post_code
        return ans

    @classmethod
    def parse(cls, code: str):
        if _GLOBAL_START in code:
            regexp = f"(?s)(?P<pre>.*){re.escape(_GLOBAL_START)}(?P<custom>.*){re.escape(_GLOBAL_END)}(?P<post>.*)"
            matched = re.fullmatch(regexp, code)
            if not matched:
                raise ValueError("Unable to parse global code", code)
            return cls(matched.group("pre"), matched.group("custom"), matched.group("post"))
        else:
            return cls(code, None, "")


@dataclass
class _FunctionCode:
    """Parsed code for a playbook function."""

    # Function header (should match _FUNC_HEADER_REGEX).
    header: str
    # Function name.
    name: str
    # String after function name but before custom code.
    pre_code: str
    # Custom code content, None for no custom code.
    custom_code: Optional[str]
    # String after custom code. Empty string if no custom code.
    post_code: str

    def __str__(self):
        ans = self.header + self.name + self.pre_code
        if self.custom_code is not None:
            ans += _LOCAL_START + self.custom_code + _LOCAL_END
        ans += self.post_code
        return ans

    @classmethod
    def parse(cls, code: str):
        regexp = f"(?s)(?P<header>{_FUNC_HEADER_REGEX})(?P<name>\w+)(?P<rest>.+)"
        matched = re.fullmatch(regexp, code)
        if not matched:
            raise ValueError("Unable to parse function code (header)", code)
        header = matched.group("header")
        name = matched.group("name")
        rest = matched.group("rest")
        if _LOCAL_START in rest:
            regexp = f"(?s)(?P<pre>.*){re.escape(_LOCAL_START)}(?P<custom>.*){re.escape(_LOCAL_END)}(?P<post>.*)"
            matched = re.fullmatch(regexp, rest)
            if not matched:
                raise ValueError("Unable to parse function code (custom code)", code)
            return cls(header, name, matched.group("pre"), matched.group("custom"), matched.group("post"))
        else:
            return cls(header, name, rest, None, "")


def _add_newline(s: str):
    """Adds newline to string s if it does not already end with a newline.

    This is the behavior of SOAR when dealing with global custom code.
    """

    if s.endswith("\n"):
        return s
    else:
        return s + "\n"


def _json_to_python_function_name(function_name: str):
    """Converts JSON data.functionName to Python function name."""

    return re.sub(r"\W", "_", function_name.lower())


@dataclass
class PlaybookBlock:
    block_id: int
    block_name: str
    block_type: str
    action_type: Optional[str]
    block_custom_name: Optional[str]
    notes: Optional[str]
    description: Optional[str]
    notes: Optional[str]
    app_info: Optional[dict]
    playbook_info: Optional[dict]
    user_code_exists: bool
    custom_function: Optional[dict]
    info: dict


class ParsedPlaybook(ParsedPlaybookOrCustomFunction):
    """Module for parsing SOAR Playbooks.
    Args:
        soar_json_code: String of the playbook JSON code
        soar_python_code: string of the python code
    Methods:
        get_playbook_blocks: Returns a list of dictionaries of all the blocks in the playbook
        get_global_code: returns any custom Global Code in the python playbook
        set_global_code: sets both the Json and Python Global Code Sections
        insert_global_code: sets the json and python playbook custom code section
        get_python_code: output python code
        get_json_code: output json code
    """

    def __init__(self, soar_name: str, soar_json_code: str, soar_python_code: str):
        assert type(soar_json_code) == str
        assert type(soar_python_code) == str
        self._check_JSON(soar_json_code)
        super().__init__(soar_name, soar_json_code, soar_python_code)
        self.coa = self.soar_json_code["coa"]
        self.soar_json_code["coa"] = None
        # self.soar_python_code is text (set by super.__init__()).
        # self._parsed_python_code is a list of _GlobalCode and _FunctionCode that parses out each function.
        # Exactly one of soar_python_code and _parsed_python_code is None.
        self._parsed_python_code = None

    @property
    def python_version(self):
        return self.coa["python_version"]

    @property
    def description(self):
        return self.coa["data"]["description"]

    @property
    def notes(self):
        return self.coa["data"]["notes"]

    @property
    def category(self):
        return self.soar_json_code["category"]

    @property
    def tags(self):
        return self.soar_json_code["tags"]

    @property
    def labels(self):
        return self.soar_json_code["labels"]

    @property
    def playbook_type(self):
        return self.coa["playbook_type"]

    @property
    def playbook_version(self):
        return self.coa["version"]

    @property
    def schema(self):
        return self.coa["schema"]

    def _check_JSON(self, soar_json_code: str) -> None:
        # Check for Valid JSON and raise error if it isnt
        try:
            json.loads(soar_json_code)
        except ValueError as error:
            raise Exception("Playbook Provided is not a valid SOAR plabook")

        # Check for Valid Playbook Json
        # essentally we are looking for a specific Key/Value Pair
        # if they dont exist its not a valid SOAR playbook and raise an exception
        try:
            json.loads(soar_json_code)["coa"]["data"]["nodes"]
        except KeyError:
            raise Exception("Playbook Provided is not a valid SOAR plabook")

    def get_playbook_blocks(self) -> list:
        """Returns a list of dictionaries of all the blocks in the playbook
        Args:
            None

        Returns:
            Returns a list of dictionaries of all the blocks in the playbook
        """
        playbook_blocks_output = []
        for block_ID, block_info in self.coa["data"]["nodes"].items():
            # Determine if this is an app block
            if "connector" in block_info["data"] and "connectorConfigs" in block_info["data"]:
                app_name = block_info["data"]["connector"]
                try:
                    connector_config = block_info["data"]["connectorConfigs"][0]
                except IndexError:
                    connector_config = None
                app_info = {"app_name": app_name, "asset_name": connector_config}
            else:
                app_info = None

            # Determine if this is a playbook block
            if "playbookName" in block_info["data"] and "playbookRepoName" in block_info["data"]:
                playbook_name = block_info["data"]["playbookName"]
                playbook_repo_name = block_info["data"]["playbookRepoName"]
                playbook_info = {"playbook_name": playbook_name, "playbook_repo_name": playbook_repo_name}
            else:
                playbook_info = None

            # Determine if there is Custom Code
            if "userCode" in block_info:
                user_code = True
            else:
                user_code = False

            block_list_item = PlaybookBlock(
                block_id=int(block_ID),
                block_name=block_info["data"]["functionName"],
                block_type=block_info["type"],
                action_type=block_info["data"].get("actionType", None),
                block_custom_name=block_info["data"].get("advanced", {}).get("customName", None),
                notes=block_info["data"].get("advanced", {}).get("note", None),
                description=block_info["data"].get("advanced", {}).get("description", None),
                app_info=app_info,
                playbook_info=playbook_info,
                user_code_exists=user_code,
                custom_function=block_info["data"].get("customFunction", None),
                info=block_info,
            )

            playbook_blocks_output.append(block_list_item)

        return playbook_blocks_output

    def get_global_code(self) -> str:
        """This returns any custom Global Code in the python playbook"""
        return self.coa["data"].get("globalCustomCode")

    def get_json_code(self) -> str:
        output_code = self.soar_json_code.copy()
        output_code["coa"] = self.coa
        return json.dumps(output_code, indent=4)

    def get_python_code(self) -> str:
        if self.soar_python_code is not None:
            assert self._parsed_python_code is None
        else:
            assert self._parsed_python_code is not None
            self.soar_python_code = "".join(map(str, self._parsed_python_code))
            self._parsed_python_code = None
        return self.soar_python_code

    def get_parsed_python_code(self) -> list[Union[_FunctionCode, _GlobalCode]]:
        """Parses Python code as necessary and returns the parsed result."""

        if self._parsed_python_code is not None:
            assert self.soar_python_code is None
        else:
            assert self.soar_python_code is not None
            # Global custom code may define functions, so we look for end of
            # global code comment and only split the code after it.
            splitted = self.soar_python_code.split(_GLOBAL_END, 1)
            assert len(splitted) in range(1, 3), "Global code end comment appears more than once"
            # Split the functions using _FUNC_HEADER_REGEX.
            fragments = re.split(f"(?<=\n)(?={_FUNC_HEADER_REGEX})", splitted[-1])
            self._parsed_python_code = [
                _GlobalCode.parse(_GLOBAL_END.join([*splitted[:-1], fragments[0]])),
                *map(_FunctionCode.parse, fragments[1:]),
            ]
            self.soar_python_code = None
        return self._parsed_python_code

    def format_python_code(self) -> None:
        """Formats Python custon code in a playbook using isort and black."""

        if self.coa["data"].get("customCode") is not None:
            raise ValueError("Full playbook is editted.")

        # Dictionary from function name to note dict object.
        fname2node = {}
        for i in self.coa["data"]["nodes"].values():
            func_name = i["data"]["functionName"]
            assert _json_to_python_function_name(func_name) not in fname2node
            fname2node[_json_to_python_function_name(func_name)] = i

        for function_code in self.get_parsed_python_code():
            if function_code.custom_code is None:
                continue
            if type(function_code) == _FunctionCode:
                prefix = "if True:\n    print(1)\n"
                suffix = "    print(2)\n"
            else:
                prefix = "print(1)\n"
                suffix = "print(2)\n"
            old_code = function_code.custom_code
            new_code = black_isort_format_str(old_code, prefix=prefix, suffix=suffix)
            if old_code == new_code:
                continue

            # Update Python code.
            function_code.custom_code = new_code

            # Update JSON code.
            if type(function_code) == _GlobalCode:
                assert self.coa["data"].get("globalCustomCode") is not None
                assert _add_newline(self.coa["data"]["globalCustomCode"]) == old_code
                self.coa["data"]["globalCustomCode"] = new_code
            else:
                assert type(function_code) == _FunctionCode
                json_node = fname2node[function_code.name]
                if json_node.get("customCode") is not None:
                    block_name = json_node["data"].get("advanced", {}).get("customName", None)
                    raise ValueError(f"Non-custom code of the function is editted for block {repr(block_name)}.")
                assert json_node.get("userCode") is not None
                assert json_node["userCode"] == old_code
                json_node["userCode"] = new_code
