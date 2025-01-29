from soar_robot_utils import ParsedPlaybook

from robot.libraries.BuiltIn import BuiltIn


class PlaybookScannerHelper:
    ROBOT_LIBRARY_SCOPE = "GLOBAL"

    def helper_parse_playbook(self, name_prefix: str) -> ParsedPlaybook:
        """Prepares a playbook for testing.

        Args:
            name_prefix: Path to playbook files, without extension.

        Returns:
            Parsed Playbook object.
        """
        pb = ParsedPlaybook.from_text(name_prefix)
        return pb

    def copy_playbook(self, pb: ParsedPlaybook) -> ParsedPlaybook:
        """Copies a playbook.

        Args:
            pb: Parsed playbook object to be copied.

        Returns:
            Copied parsed Playbook object.
        """
        return ParsedPlaybook.from_b64(pb.to_b64())
