*** Settings ***
Documentation    One actual source-bound SteamOS output phase. No adapters or simulated transitions.
Library          opemos_output_phase_controller.OPEMOSSteamOS
Test Teardown    Close Native Output Phase
Test Timeout     ${PHASE_TIMEOUT}

*** Test Cases ***
Ordinary Output Installation And Installed Health Phase
    Verify Exact Guest Target
    Execute Ordinary Output Phase
    Verify Current Output Phase
