*** Settings ***
Documentation    Actual pointer operation in the exact ordinary admitted transaction.
Library    ../../scripts/OPEMOSPointer.py

*** Test Cases ***
Real mouse input and independently observed result
    Click Observed Native Control    %{OPEMOS_POINTER_OPERATION}    %{OPEMOS_POINTER_OPERATION_SHA256}
    Assert Current Observed Result    %{OPEMOS_POINTER_OPERATION}    %{OPEMOS_POINTER_OPERATION_SHA256}
