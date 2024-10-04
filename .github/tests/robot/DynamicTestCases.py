"""Supports dynamically adding a test case during robot framework execution.

Adapted from https://stackoverflow.com/a/77484465 .
"""

# While this import does not seem necessary, it was useful in the python console.
from robot.running.model import Keyword, TestCase, TestSuite


class DynamicTestCases(object):
    ROBOT_LISTENER_API_VERSION = 3
    ROBOT_LIBRARY_SCOPE = "TEST SUITE"

    def __init__(self):
        self.ROBOT_LIBRARY_LISTENER = self
        self._current_suite = None

    def _start_suite(self, suite, result):
        # Don't change the name of this method.
        # save current suite so that we can modify it later
        self._current_suite = suite

    def dynamic_test_cases_create(self, name, *tags):
        """Adds a test case to the current suite.

        Args:
            name: is the test case name
            tags: is a list of tags to add to the test case

        Returns: The test case that was added
        """
        test_case = self._current_suite.tests.create(name=name, tags=tags)
        return test_case

    def dynamic_test_cases_set_body(self, test_case: TestCase, keyword_name: str, *args) -> Keyword:
        """Sets the body keyword of the given test case.

        Args:
            test_case: The test case to add the keyword to.
            keyword_name: The name of the keyword to add.
            args: The arguments to pass to the keyword. Currently only support
              positional arguments.
        """
        keyword = test_case.body.create_keyword(name=keyword_name, args=args)
        return keyword

    def dynamic_test_cases_set_setup(self, test_case: TestCase, keyword_name: str, *args) -> Keyword:
        """Sets the setup keyword of the given test case.

        Args:
            test_case: The test case to add the keyword to.
            keyword_name: The name of the keyword to add.
            args: The arguments to pass to the keyword. Currently only support
              positional arguments.
        """
        keyword = test_case.body.create_keyword(name=keyword_name, args=args, type="setup")
        test_case.setup = keyword
        return keyword

    def dynamic_test_cases_set_teardown(self, test_case: TestCase, keyword_name: str, *args) -> Keyword:
        """Sets the teardown keyword of the given test case.

        Args:
            test_case: The test case to add the keyword to.
            keyword_name: The name of the keyword to add.
            args: The arguments to pass to the keyword. Currently only support
              positional arguments.
        """
        keyword = test_case.body.create_keyword(name=keyword_name, args=args, type="teardown")
        test_case.teardown = keyword
        return keyword
