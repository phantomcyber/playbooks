*** Settings ***
Documentation       Scan playbook to make sure it follows MR review standard.
...
...                 https://docs.google.com/document/d/1cowcKOZxcc7U90eP5Zy1j5HtLhLQCg9_ALtSOTC_CYE/edit

Library             OperatingSystem
Library             String
Library             DynamicTestCases.py


*** Variables ***
${files}             %{FILES=}


*** Test Cases ***
Test Automation Code
    # Can we get generate this list automatically? Asked on https://stackoverflow.com/q/78794730
    ${tests}=    Create List
    ...    Scan Code Pylint

    Log    ${files}

    ${split_files}=    Split String    ${files}

    FOR    ${file}    IN    @{split_files}
        FOR    ${i}    IN    @{tests}
            ${test_case}=    Dynamic Test Cases Create    Test ${i} ${file}
            Dynamic Test Cases Set Body    ${test_case}    ${i}    ${file}
        END
    END


*** Keywords ***
Scan Code Pylint
    [Documentation]    Make sure code passes some of the basic pylint checks enforced by the VPE and custom function editor
    [Arguments]    ${file}

    ${result}    Run    pylint --enable=E,F --disable=W,C,R,I,E0401 ${file}  # only check for error and fatal, ignore E0401 (import-error) since we don't have the dependencies
    ${lines}=    Split String    ${result}    \n
    ${line_count}=    Get Length    ${lines}
    Should Be Equal as Integers   ${line_count}    4    ${result}