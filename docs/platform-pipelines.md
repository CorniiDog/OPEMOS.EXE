# Platform executable pipelines

The Actions entries name the host platform and exact executable format:

| Workflow | Built executable | Result scope |
| --- | --- | --- |
| 01 Windows EXE | Unsigned portable x86-64 Windows executable and pinned runtime | Existing Windows compilation, package and startup checks |
| 02 Ubuntu AppImage | Ubuntu 24.04 x86-64 AppImage and Debian package | Actual Ubuntu-host packaging, checksums, source provenance and pinned Fedora companion |
| 03 macOS Executable | Native Apple-silicon macOS bundle | Existing macOS producer and real graphical test when its required current-source files are present |

The existing Checks workflow retains its separate Debian 12 container qualification.
The Ubuntu workflow builds on an actual Ubuntu 24.04 runner.

The macOS entry checks the current commit for the existing native packaging and
graphical producer before acquisition or compilation. Those source files are
currently being developed in the macOS implementation pull request. Until they
land, this entry fails with the exact missing file. It does not switch to a
different branch or report another commit's artifact as the current result.

Executable packaging, real graphical image creation, virtual-USB writing with
full readback, virtual SteamOS installation and NVIDIA recovery are distinct
gates. These workflow entries do not mark the full stack passed. All USB testing
uses owned file-backed virtual devices; no physical USB is attached or written.
The separate OMEN SSH/all-VM integration and four-hour artifact retention remain
under validation and are not activated by this naming and packaging change.
