*** Settings ***
Documentation    Fresh admitted transactions. Every missing/broken VM is FAIL, never SKIP.
Library    ../../scripts/OPEMOSRobot.py
Suite Teardown    Retain Independent Outcomes

*** Test Cases ***
Scoped retained-package Ubuntu chooser connection only
    [Documentation]    Real GitHub/broker/queue/pointer/native chooser connection using retained 01ae AppImage. NOT current-head image/USB/SteamOS/NVIDIA acceptance.
    [Tags]    connection-only    old-artifact    no-fullstack-acceptance
    Prove Scoped Ubuntu Connection

OPEMOS-Agent-Boot
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    81688cb8-c3a5-41c3-b7a3-75a9f6ba0e25

OPEMOS-Agent-Boot-B
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    c54ddf9a-6060-44d7-9cd2-3476e8b4d996

OPEMOS-Agent-UI
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    9dc1d978-a83a-4699-aeb9-32c10fe22be3

OPEMOS-Agent-UI-B
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    d058543e-5b8c-4742-93a4-5bd2427621d8

OPEMOS-KVM-A
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    97ad3a89-299d-44e6-92bc-880e197d2f89

OPEMOS-KVM-B
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    130f2dc3-24b4-403f-8e28-7f1776251a15

OPEMOS-Windows-Test
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    d6011de4-0376-4109-a569-31ad00418f5d

OPEMOS-Windows-Test-B
    [Tags]    inventory    transferred-hyperv
    Execute Exact VM    9f63f6d9-a223-492d-8f68-49ef3948838d

OPEMOS-Ubuntu-Test
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Test

OPEMOS-Ubuntu-Test-B
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Test-B

OPEMOS-Ubuntu-Agent-Boot
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Agent-Boot

OPEMOS-Ubuntu-Agent-Boot-B
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Agent-Boot-B

OPEMOS-Ubuntu-Agent-UI
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Agent-UI

OPEMOS-Ubuntu-Agent-UI-B
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-Agent-UI-B

OPEMOS-Ubuntu-KVM-A
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-KVM-A

OPEMOS-Ubuntu-KVM-B
    [Tags]    inventory    ubuntu-counterpart
    Execute Exact VM    OPEMOS-Ubuntu-KVM-B

Admitted Apple Silicon macOS graphical lane
    [Tags]    inventory    macos
    Execute Exact VM    macos-apple-silicon-fullstack

Same SteamOS guest kernel update/NVIDIA/render/power recovery
    [Tags]    inventory    steamos
    Execute Exact VM    steamos-same-guest-gpu-autoheal

opemos-windows-debloat-20261019-r3b
    [Tags]    inventory    fresh-windows-install
    Execute Exact VM    opemos-windows-debloat-20261019-r3b

OPEMOS-Ubuntu-FullStack-PR189-20261019-r1
    [Tags]    inventory    ubuntu-graphical-fullstack
    Execute Exact VM    OPEMOS-Ubuntu-FullStack-PR189-20261019-r1

windows executable SteamOS outputs
    [Tags]    executable    windows
    Execute Every Platform Artifact    windows

ubuntu executable SteamOS outputs
    [Tags]    executable    ubuntu
    Execute Every Platform Artifact    ubuntu

macos executable SteamOS outputs
    [Tags]    executable    macos
    Execute Every Platform Artifact    macos

