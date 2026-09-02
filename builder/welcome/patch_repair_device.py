#!/usr/bin/env python3

"""Create the protected Open OPEMOS delegate from a compatible Valve installer."""

from pathlib import Path
import os
import sys


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"Open OPEMOS installer patch: {message}")


if len(sys.argv) != 3:
    fail("usage: patch_repair_device.py SOURCE OUTPUT")

source = Path(sys.argv[1])
output = Path(sys.argv[2])
if source.is_symlink() or not source.is_file():
    fail("Valve repair_device.sh must be a regular file")
text = source.read_text(encoding="utf-8")
replacements = (
    (
        "DISK=/dev/nvme0n1\nDISK_SUFFIX=p\n",
        'DISK="${STEAMOS_TARGET_DISK:?Open OPEMOS requires an explicit target disk}"\n'
        'DISK_SUFFIX=""\n'
        '[[ "$DISK" =~ [0-9]$ ]] && DISK_SUFFIX=p\n',
    ),
    (
        "prompt_reboot()\n{\n  local msg=$1\n",
        "prompt_reboot()\n{\n  local msg=$1\n"
        "  if [[ ${OPEMOS_NO_REBOOT:-0} == 1 ]]; then\n"
        "    estat \"$msg Open OPEMOS will let the user choose when to shut down.\"\n"
        "    return 0\n"
        "  fi\n",
    ),
    (
        "  if [[ $writeOS = 1 ]]; then\n"
        "    # Set up ESP/EFI boot partitions\n",
        "  if [[ $writeOS = 1 ]]; then\n"
        "    # Set up ESP/EFI boot partitions\n",
    ),
    (
        "  # Stage a BIOS update for next reboot if updating OS. OOBE images like this one don't auto-update the bios on boot.\n"
        "  if [[ $writeOS = 1 ]]; then\n",
        "  # Generic OPEMOS targets must not run Steam Deck-specific firmware tools.\n"
        "  if [[ $writeOS = 1 && ${OPEMOS_SKIP_JUPITER_FIRMWARE:-0} != 1 ]]; then\n",
    ),
    (
        "  # Perform a controller update if updating OS.  OOBE images like this one don't auto-update controllers on boot.\n"
        "  if [[ $writeOS = 1 ]]; then\n",
        "  # Perform a controller update only on an explicitly supported Steam Deck path.\n"
        "  if [[ $writeOS = 1 && ${OPEMOS_SKIP_JUPITER_FIRMWARE:-0} != 1 ]]; then\n",
    ),
    (
        "  writeHome=1\n  sanitize_all\n  repair_steps\n",
        "  writeHome=1\n"
        "  ewarn \"Open OPEMOS skips firmware secure erase; repartitioning and filesystem creation follow.\"\n"
        "  repair_steps\n",
    ),
)

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        fail(f"unsupported Valve installer structure for guarded anchor ({count} matches)")
    text = text.replace(old, new, 1)

hang_count = text.count("sleep infinity")
if hang_count != 5:
    fail(f"unsupported Valve installer error-wait contract ({hang_count} matches)")
text = text.replace(
    "sleep infinity",
    '[[ ${OPEMOS_FAIL_FAST:-0} == 1 ]] || sleep infinity',
)

required = (
    'DISK="${STEAMOS_TARGET_DISK:?Open OPEMOS requires an explicit target disk}"',
    '[[ "$DISK" =~ [0-9]$ ]] && DISK_SUFFIX=p',
    "OPEMOS_SKIP_JUPITER_FIRMWARE",
    "OPEMOS_NO_REBOOT",
    "OPEMOS_FAIL_FAST",
    'echo "$PARTITION_TABLE" | sfdisk "$DISK"',
    'steamos-chroot --no-overlay --disk "$DISK"',
)
for marker in required:
    if marker not in text:
        fail(f"patched installer is missing required marker: {marker}")

output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
if output.exists() or output.is_symlink():
    if output.is_symlink() or not output.is_file():
        fail("existing protected installer delegate is not a regular file")
    stat = output.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        fail("existing protected installer delegate has unsafe ownership or mode")
    if output.read_text(encoding="utf-8") != text:
        fail("existing protected installer delegate does not match the guarded result")
    raise SystemExit(0)
fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
    stream.write(text)
