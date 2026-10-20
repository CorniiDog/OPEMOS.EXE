*** Settings ***
Library    Process
Library    OperatingSystem

*** Test Cases ***
Current Packaged Finder Pointer Build And Independent Completed Image
    ${python}=    Get Environment Variable    OPEMOS_MAC_ROBOT_PYTHON
    ${result}=    Run Process    ${python}    scripts/check_macos_arm64_ci.py    stdout=${OUTPUT DIR}/native-transaction.log    stderr=STDOUT
    Should Be Equal As Integers    ${result.rc}    0    Actual native producer/GUI/image/fault/finalizer failed; retained exact native receipt and log.
