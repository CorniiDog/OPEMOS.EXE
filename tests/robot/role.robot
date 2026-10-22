*** Settings ***
Documentation    Actual non-GUI guest identity; complete role receipt and closure remain mandatory.
Library    ../../scripts/OPEMOSGuest.py

*** Test Cases ***
Exact current non-graphical guest role
    Verify Current Guest Identity
