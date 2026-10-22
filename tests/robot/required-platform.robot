*** Settings ***
Documentation    Exact producer artifact: real GUI Build, image, virtual USB, SteamOS and NVIDIA. Unavailable is FAIL.
Library    ../../scripts/OPEMOSRobot.py
Suite Teardown    Retain Independent Outcomes

*** Test Cases ***
Required exact produced executable graphical image and SteamOS transaction
    Execute Exact Produced Platform
