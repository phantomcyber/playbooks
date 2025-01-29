*** Settings ***
Documentation       Scan playbook to make sure it follows MR review standard.
...
...                 https://docs.google.com/document/d/1cowcKOZxcc7U90eP5Zy1j5HtLhLQCg9_ALtSOTC_CYE/edit

Library             PlaybookScannerHelper.py
Library             DynamicTestCases.py


*** Variables ***
${playbook}             %{PLAYBOOK=}
${EXAMPLE_PLAYBOOK}=    repos/community2/Jira_Related_Tickets_Search

@{block_types}=         Create List
...                     start
...                     end
...                     action
...                     playbook
...                     code
...                     utility
...                     filter
...                     decision
...                     format
...                     prompt


*** Test Cases ***
Test Playbook
    # Can we get generate this list automatically? Asked on https://stackoverflow.com/q/78794730
    ${tests}=    Create List
    ...    Scan Playbook Name
    ...    Scan Playbook Category
    ...    Scan Playbook Description
    ...    Scan Playbook Notes
    ...    Scan Playbook Block Count
    ...    Scan Playbook Custom List Ref
    ...    Scan Block Names
    ...    Scan Block Notes
    ...    Scan Custom Code
    ...    Scan Start End Block
    ...    Scan Decision Filter Block
    ...    Scan Action Block
    ...    Scan Utility Playbook Block
    ...    Scan Automation Playbook Label
    ...    Scan Automation Playbook Paths
    ...    Scan Input Playbook Start Block
    ...    Scan Input Playbook Tags
    ...    Scan Global Custom Code
    ...    Scan Unbounded Custom Code
    ...    Scan Code Formatting

    IF    ${{not $playbook}}
        ${playbook}=    Set Variable    ${EXAMPLE_PLAYBOOK}
    END

    Log    ${playbook}
    ${pb}=    Helper Parse Playbook    ${playbook}

    FOR    ${i}    IN    @{tests}
        ${test_case}=    Dynamic Test Cases Create    Test ${i}
        Dynamic Test Cases Set Body    ${test_case}    ${i}    ${pb}
    END


*** Keywords ***
Get Playbook Blocks By Type
    [Documentation]    Returns desired types of blocks in the playbook.
    [Arguments]    ${pb}    @{types}

    # Input validation.
    Should Be Equal    ${{len($types)}}    ${{len(set($types))}}    "types" list contains duplicate values
    FOR    ${type}    IN    @{types}
        Should Contain    ${block_types}    ${type}
    END

    # Compute answer.
    @{ans}=    Create List
    FOR    ${block}    IN    @{{$pb.get_playbook_blocks()}}
        IF    ${{$block.block_type in $types}}
            @{ans}=    Create List    @{ans}    ${block}
        END
    END
    RETURN    ${ans}

Scan Playbook Name
    [Documentation]    Playbook name is A-Z in Title case with underscores between words. (e.g.
    ...    MS_Graph_Search_and_Purge)
    [Arguments]    ${pb}
    Log    ${pb.name}

    ${regex_word}=    Set Variable    [0-9A-Z][0-9A-Za-z]*
    ${regex_name}=    Set Variable    ^${regex_word}(?:_${regex_word})*$
    Should Match Regexp    ${pb.name}    ${regex_name}

Scan Playbook Category
    [Documentation]    Category in Title case with spaces between words (e.g. Identifier Reputation Analysis)
    [Arguments]    ${pb}
    Log    ${pb.category}

    ${regex_word}=    Set Variable    [0-9A-Z][0-9A-Za-z]*
    ${regex_name}=    Set Variable    ^${regex_word}(?: ${regex_word})*$
    Should Match Regexp    ${pb.category}    ${regex_name}

Scan Playbook Description
    [Documentation]    Description is free of grammatical errors and describe what the playbook does.
    [Arguments]    ${pb}
    Log    ${pb.description}

    Should Not Be Empty    ${pb.description}
    Skip    Please check playbook description manually.

Scan Playbook Notes
    [Documentation]    Notes list any setup required on the third-party API as well as intended areas for customization.
    [Arguments]    ${pb}
    Log    ${pb.notes}

    Should Not Be Empty    ${pb.notes}
    Skip    Please check playbook notes manually.

Scan Playbook Block Count
    [Documentation]    Playbook block count not greater than 20 (not including Start and End blocks).
    [Arguments]    ${pb}

    ${block_count}=    Set Variable    ${{len($pb.get_playbook_blocks()) - 2}}
    IF    ${{$block_count > 20}}
        Fail    Block count ${block_count} is greater than 20
    END

Scan Playbook Custom List Ref
    [Documentation]    If referencing a custom list, Notes document what the expected values are in that custom list.
    [Arguments]    ${pb}

    Skip    Please check custom list references manually.

Scan Block Names
    [Documentation]    All blocks have a custom name no more than 4 words, all lowercase, and separated by space (e.g.
    ...    close workbook task)
    [Arguments]    ${pb}

    ${fail_count}=    Set Variable    ${0}

    ${regex_word}=    Set Variable    [0-9a-z]+
    ${regex_name}=    Set Variable    ${regex_word}( ${regex_word}){0,3}

    FOR    ${block}    IN    @{{$pb.get_playbook_blocks()}}
        IF    ${{$block.block_type in ("start", "end")}}
            Log    Start and end blocks do not need to be named.
        ELSE IF    ${{$block.block_custom_name is None}}
            Log    Block ${{repr($block.block_name)}} is not named    ERROR
            ${fail_count}=    Set Variable    ${{$fail_count + 1}}
        ELSE
            ${block_name}=    Set Variable    ${{$block.block_custom_name}}
            ${passed}=    Run Keyword And Return Status    Should Match Regexp    ${block_name}    ^${regex_name}$
            Log    ${block_name}
            IF    ${{not $passed}}
                Log    Block name not following standard: ${block_name}    ERROR
                ${fail_count}=    Set Variable    ${{$fail_count + 1}}
            END
        END
    END

    IF    ${{$fail_count > 0}}
        Fail    ${fail_count} errors found in block names.
    END

Scan Block Notes
    [Documentation]    All blocks that support a Notes Tooltip have it filled out. Must be grammatically correct and
    ...    describes the intended purpose of that block.
    [Arguments]    ${pb}

    @{notes_supported}=    Create List
    ...    action
    ...    code
    ...    utility
    ...    filter
    ...    decision
    ...    format
    ...    prompt
    @{notes_not_supported}=    Create List
    ...    start
    ...    end
    ...    playbook

    ${fail_count}=    Set Variable    ${0}

    FOR    ${block}    IN    @{{$pb.get_playbook_blocks()}}
        IF    ${{$block.block_type in $notes_supported}}
            IF    ${{not $block.notes}}
                Log    Block ${{repr($block.block_name)}} does not have notes    ERROR
                ${fail_count}=    Set Variable    ${{$fail_count + 1}}
            END
        ELSE IF    ${{$block.block_type in $notes_not_supported}}
            Log    Notes not supported for block ${{repr($block.block_name)}}
        ELSE
            Fail    Unknown block type: ${block.block_type}
        END
    END

    IF    ${{$fail_count > 0}}
        Fail    ${fail_count} errors found in block notes.
    END

    Skip    Please check notes content manually.

Scan Custom Code
    [Documentation]    Where custom code is used, block notes indicate presence of custom code (e.g. "This block uses
    ...    custom code")
    ...
    ...    No block is disabled by custom code
    ...
    ...    Custom code is documented with notes
    ...
    ...    Debug statements are removed or commented out
    [Arguments]    ${pb}

    @{custom_code_blocks}=    Create List

    FOR    ${block}    IN    @{{$pb.get_playbook_blocks()}}
        IF    ${block.user_code_exists}
            @{custom_code_blocks}=    Create List    @{custom_code_blocks}    ${block.block_name}
        END
    END

    Skip If    ${{len($custom_code_blocks) > 0}}    Please check custom code manually: ${custom_code_blocks}.

Scan Start End Block
    [Documentation]    No custom code of any kind in Start and End blocks
    [Arguments]    ${pb}

    ${blocks}=    Get Playbook Blocks By Type    ${pb}    start    end
    @{failed_blocks}=    Create List

    FOR    ${block}    IN    @{blocks}
        IF    ${block.user_code_exists}
            Log    Block ${{repr($block.block_name)}} contains custom code    ERROR
            @{failed_blocks}=    Create List    @{failed_blocks}    ${block.block_name}
        END
    END

    Should Be Empty    ${failed_blocks}

Scan Decision Filter Block
    [Documentation]    All condition paths have a custom label
    [Arguments]    ${pb}

    ${blocks}=    Get Playbook Blocks By Type    ${pb}    decision    filter
    @{failed_blocks}=    Create List

    FOR    ${block}    IN    @{blocks}
        FOR    ${condition}    IN    @{block.info["data"]["conditions"]}
            IF    ${{$condition.get("customName") is None}}
                Log    Not all conditions in block ${{repr($block.block_name)}} are labeled    ERROR
                @{failed_blocks}=    Create List    @{failed_blocks}    ${block.block_name}
                BREAK
            END
        END
    END

    Should Be Empty    ${failed_blocks}

Scan Action Block
    [Documentation]    Use apps available on Splunkbase
    ...
    ...    Use asset names that are the app name, all lowercase separated by underscores (e.g. Azure AD Graph becomes
    ...    azure_ad_graph)
    [Arguments]    ${pb}

    ${blocks}=    Get Playbook Blocks By Type    ${pb}    action
    @{failed_blocks}=    Create List

    FOR    ${block}    IN    @{blocks}
        ${app_name}=    Set Variable    ${block.app_info["app_name"]}
        ${asset_name}=    Set Variable    ${block.app_info["asset_name"]}
        ${expected_asset_name}=    Set Variable    ${app_name.lower().replace(" ", "_")}
        IF    ${{$expected_asset_name != $asset_name}}
            Log    Incorrect asset name in block ${{repr($block.block_name)}}    ERROR
            @{failed_blocks}=    Create List    @{failed_blocks}    ${block.block_name}
        END
    END

    Should Be Empty    ${failed_blocks}
    Skip If    ${{len($blocks) > 0}}    Please check whether apps are from Splunkbase manually

Scan Utility Playbook Block
    [Documentation]    Block is using local version
    [Arguments]    ${pb}

    ${blocks}=    Get Playbook Blocks By Type    ${pb}    playbook
    @{failed_blocks}=    Create List

    FOR    ${block}    IN    @{blocks}
        ${playbook_name}=    Set Variable    ${block.playbook_info["playbook_name"]}
        ${repo_name}=    Set Variable    ${block.playbook_info["playbook_repo_name"]}
        IF    ${{$repo_name != "community"}}
            Log    Subplaybook is not using community version in block ${{repr($block.block_name)}}    ERROR
            @{failed_blocks}=    Create List    @{failed_blocks}    ${block.block_name}
        END
    END

    Should Be Empty    ${failed_blocks}

Scan Automation Playbook Label
    [Documentation]    Automation Playbooks: Label is set to '\*'
    [Arguments]    ${pb}

    IF    ${{$pb.coa["playbook_type"] == "automation"}}
        Log    ${pb.labels}
        Should Be Equal    ${pb.labels}    ${{["*"]}}
    END

Scan Automation Playbook Paths
    [Documentation]    Automation Playbooks: No more than 3 concurrent branching paths.
    [Arguments]    ${pb}

    IF    ${{$pb.coa["playbook_type"] == "automation"}}
        Skip    Please check number of branching paths manually.
    END

Scan Input Playbook Start Block
    [Documentation]    Input Playbooks: Start blocks use ocsf variable names and a minimum of one data type per variable
    ...    name (e.g. device (type: host name))
    ...
    ...    Start blocks use a specific data type if playbooks is expecting it (e.g. user (type: user name, aws iam user
    ...    name))
    [Arguments]    ${pb}

    IF    ${{$pb.coa["playbook_type"] == "data"}}
        Skip    Please check start block manually.
    END

Scan Input Playbook Tags
    [Documentation]    Input Playbooks: Has at least one category tag (e.g. reputation)
    ...
    ...    Playbook has a tag for each vendor app used (e.g. crowdstrike, virustotal, etc.)
    ...
    ...    Playbook has a tag for each input type (e.g. host name, user)
    ...
    ...    If applicable, Playbook has a tag for each D3FEND technique (e.g. D3-DA)
    [Arguments]    ${pb}

    IF    ${{$pb.coa["playbook_type"] == "data"}}
        Log    ${pb.tags}
        Should Not Be Empty    ${pb.tags}    According to the requirement there should be at least 1 tag.
        Skip    Please check playbook tags manually.
    END

Scan Global Custom Code
    [Documentation]    Make sure there is no global custom code.
    [Arguments]    ${pb}

    Should Be Equal    ${{$pb.get_global_code()}}    ${None}

Scan Unbounded Custom Code
    [Documentation]    Make sure custom code are inside custom code region.
    [Arguments]    ${pb}

    Should Be Equal    ${{$pb.coa["data"].get("customCode")}}    ${None}
    FOR    ${block}    IN    @{{$pb.get_playbook_blocks()}}
        Should Be Equal    ${{$block.info.get("customCode")}}    ${None}
    END

Scan Code Formatting
    [Documentation]    Make sure custom code are formatted.
    [Arguments]    ${pb}

    ${pb_copy}=    Copy Playbook    ${pb}
    Log    ${pb_copy.format_python_code()}

    ${old_code}=    Set Variable    ${pb.get_python_code()}
    ${new_code}=    Set Variable    ${pb_copy.get_python_code()}

    # Currently do not enforce code formatting.
    ${passed}=    Run Keyword And Return Status    Should Be Equal    ${old_code}    ${new_code}
    Skip If    ${{not $passed}}    Custom code is not formatted
