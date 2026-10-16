"""Source-prepared original AgentBoot trust-preserving offline VARS derivative.

Not launch authority. Never execute on originals or on a physical firmware
device. Only the four reviewed original data variables are imported; other
VMGS contents (including private machine state) are never exported or logged.
No downloads, default keys, .ms store, key generation, or runtime attestations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import uuid

VMGS_SHA = '161ba6a3009053c0c689ba14ed7cbd64903aca66080e6a9e84cd25c4944e7f85'
TEMPLATE_SHA = '5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e'
CODE_SHA = '1286f2a3217d09b374d05951355d7a561c8bacecd74845c8a1fbb71a48c0de8d'
GLOBAL = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
DATABASE = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
ENABLE = 'f0a30bc7-af08-4556-99c4-001009c93a44'
STORE = uuid.UUID('aaf32c78-947b-439a-a180-2e144ec37792').bytes_le
PINS = {
    'PK': (GLOBAL, 1862, '72d3af9b2b57cfd0c1fcafc28babaa2212428c6604c1ac0b624fafbf28ac88e7'),
    'KEK': (GLOBAL, 3066, 'cc3a5dbc7b3aec3b60c0da33510bf93f402479bbf445dc360e6111afa70c6342'),
    'db': (DATABASE, 3041, '584ff437815864a48a2e4c1cc13af8bc19471b140c8085e9de7c738354a91fdc'),
    'dbx': (DATABASE, 21444, '8854a8d94d7ac7810685f806b73fc5cdc27eae655b0e0a246674a8e4f9cf9c49'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def read_pinned(path, length, sha):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('direct absolute input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid not in (0, os.getuid()) or before.st_size != length):
            raise ValueError('unsafe exact input identity/size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(length + 1)
        after = os.fstat(fd)
        current = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(current) or
                len(data) != length or digest(data) != sha):
            raise ValueError('input changed or hash mismatch')
        return data, list(identity(after))
    finally:
        os.close(fd)


def original_variables(vmgs):
    if len(vmgs) != 4194816 or digest(vmgs) != VMGS_SHA:
        raise ValueError('exact retained AgentBoot VMGS required')
    copies = []
    for offset in (18432, 2097664):
        end = offset
        while end < offset + 1_000_000 and vmgs[end:end + 2] != b'\0\0':
            end += 2
        if end >= offset + 1_000_000:
            raise ValueError('bounded terminated VMGS JSON required')
        source = json.loads(vmgs[offset:end].decode('utf-16-le'), object_pairs_hook=no_duplicate_pairs)
        vendors = source['Devices']['ac6b8dc1-3257-4a70-b1b2-a9c9215659ad']['States']['Nvram']['Vendors']
        selected = {}
        for name, (guid, length, sha) in PINS.items():
            row = vendors[guid]['Variables'][name]
            data = row.get('Data')
            if (type(row.get('Attributes')) is not int or row['Attributes'] != 39 or
                    not isinstance(data, list) or len(data) != length or
                    any(type(v) is not int or not 0 <= v <= 255 for v in data)):
                raise ValueError('original variable shape/attribute mismatch: ' + name)
            value = bytes(data)
            if digest(value) != sha:
                raise ValueError('original variable hash mismatch: ' + name)
            selected[name] = value
        copies.append(selected)
    if copies[0] != copies[1]:
        raise ValueError('redundant original trust variables differ')
    return copies[0]


def store_region(image):
    # EDK2 stable202402 VariableFormat.h: FV followed by28-byte authenticated
    # store header,60-byte authenticated variable headers aligned to4 bytes.
    if (len(image) != 540672 or image[40:44] != b'_FVH' or
            struct.unpack_from('<Q', image, 32)[0] != len(image)):
        raise ValueError('exact OVMF4M VARS geometry required')
    header = struct.unpack_from('<H', image, 48)[0]
    if header != 72 or sum(struct.unpack('<36H', image[:72])) & 0xffff:
        raise ValueError('firmware volume header/checksum mismatch')
    signature, size, fmt, healthy, reserved, reserved1 = struct.unpack_from('<16sIBBHI', image, header)
    if (signature != STORE or size != 262072 or fmt != 0x5a or healthy != 0xfe or
            reserved != 0 or reserved1 != 0):
        raise ValueError('unknown authenticated variable store')
    return header + 28, header + size


def inspect_store(image):
    """Independent bounded header walk, not writer offsets or a manifest flag."""
    pos, end = store_region(image)
    records = {}
    while pos < end and image[pos:pos + 2] != b'\xff\xff':
        if len(records) >= 5 or pos + 60 > end:
            raise ValueError('excess or truncated firmware records')
        start, state, reserved, attrs, monotonic, timestamp, key, namesize, datasize, guid = struct.unpack_from(
            '<HBBIQ16sIII16s', image, pos)
        finish = pos + 60 + namesize + datasize
        if (start != 0x55aa or state != 0x3f or reserved != 0 or
                monotonic != 0 or timestamp != bytes(16) or key != 0 or
                not 2 <= namesize <= 128 or namesize % 2 or finish > end):
            raise ValueError('invalid authenticated variable record')
        namebytes = image[pos + 60:pos + 60 + namesize]
        if namebytes[-2:] != b'\0\0':
            raise ValueError('unterminated variable name')
        name = namebytes[:-2].decode('utf-16-le')
        if name in records or '\0' in name:
            raise ValueError('duplicate or ambiguous variable')
        value = image[pos + 60 + namesize:finish]
        records[name] = (str(uuid.UUID(bytes_le=guid)), attrs, value)
        nextpos = (finish + 3) & ~3
        if image[finish:nextpos] != b'\xff' * (nextpos - finish):
            raise ValueError('non-erased variable alignment')
        pos = nextpos
    if image[pos:end] != b'\xff' * (end - pos):
        raise ValueError('hidden trailing variable data')
    return records


def build_derivative(template, variables):
    if digest(template) != TEMPLATE_SHA or set(variables) != set(PINS):
        raise ValueError('exact blank template and four originals required')
    begin, end = store_region(template)
    if template[begin:end] != b'\xff' * (end - begin):
        raise ValueError('template is not empty; never merge default keys')
    rows = []
    for name, (guid, length, sha) in PINS.items():
        value = variables[name]
        if len(value) != length or digest(value) != sha:
            raise ValueError('refuse altered original trust input: ' + name)
        rows.append((name, guid, 39, value))
    rows.append(('SecureBootEnable', ENABLE, 3, b'\x01'))
    payload = bytearray()
    for name, guid, attrs, value in rows:
        encoded = name.encode('utf-16-le') + b'\0\0'
        payload.extend(struct.pack('<HBBIQ16sIII16s', 0x55aa, 0x3f, 0, attrs, 0,
                                   bytes(16), 0, len(encoded), len(value), uuid.UUID(guid).bytes_le))
        payload.extend(encoded); payload.extend(value)
        payload.extend(b'\xff' * (-len(payload) % 4))
    if len(payload) > end - begin:
        raise ValueError('original trust data exceeds fixed store')
    result = template[:begin] + payload + template[begin + len(payload):]
    verify_derivative(result)
    return result


def verify_derivative(image):
    observed = inspect_store(image)
    if set(observed) != set(PINS) | {'SecureBootEnable'}:
        raise ValueError('missing original or additional firmware variable')
    for name, (guid, length, sha) in PINS.items():
        actual_guid, attrs, value = observed[name]
        if (actual_guid != guid or attrs != 39 or len(value) != length or digest(value) != sha):
            raise ValueError('independent original trust re-read failed: ' + name)
    if observed['SecureBootEnable'] != (ENABLE, 3, b'\x01'):
        raise ValueError('SecureBootEnable must be On')
    return {name: digest(observed[name][2]) for name in PINS}


def prepare(vmgs_path, code_path, template_path, destination):
    """Only invoke after separate create-only staging admission; never boots."""
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('original AgentBoot derivative must be created as UID1000, not root')
    vmgs, vmgs_id = read_pinned(vmgs_path, 4194816, VMGS_SHA)
    code, code_id = read_pinned(code_path, 3653632, CODE_SHA)
    template, template_id = read_pinned(template_path, 540672, TEMPLATE_SHA)
    image = build_derivative(template, original_variables(vmgs))
    destination = Path(destination)
    parent = destination.parent
    info = parent.lstat()
    if (not destination.is_absolute() or parent.resolve() != parent or
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('exact private owned staging parent required')
    parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    outputfd = None
    try:
        bound = os.fstat(parentfd)
        if (bound.st_dev, bound.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('staging parent replaced')
        os.mkdir(destination.name, 0o700, dir_fd=parentfd)  # no reuse/recovery
        os.fsync(parentfd)
        outputfd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                           os.O_CLOEXEC, dir_fd=parentfd)
        fd = os.open('agentboot-original-vars.fd', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=outputfd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(image); stream.flush(); os.fsync(stream.fileno())
            created = os.fstat(stream.fileno())
        reread, output_id = read_pinned(destination / 'agentboot-original-vars.fd', 540672, digest(image))
        if output_id[:2] != [created.st_dev, created.st_ino]:
            raise ValueError('derived file path replaced; preserve partials')
        pins = verify_derivative(reread)
        for path, length, sha, identity in [(vmgs_path, 4194816, VMGS_SHA, vmgs_id),
                                          (code_path, 3653632, CODE_SHA, code_id),
                                          (template_path, 540672, TEMPLATE_SHA, template_id)]:
            if read_pinned(path, length, sha)[1] != identity:
                raise ValueError('input identity changed; preserve partial derivative')
        current = destination.lstat()
        pinned = os.fstat(outputfd)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise ValueError('output directory path replaced')
        receipt = {'sourceVMGSsha256': VMGS_SHA, 'sourceIdentity': vmgs_id,
                   'CODEsha256': digest(code), 'CODEidentity': code_id,
                   'blankTemplateSha256': TEMPLATE_SHA, 'templateIdentity': template_id,
                   'derivativeSha256': digest(reread), 'derivativeIdentity': output_id,
                   'originalVariableSha256': pins, 'SecureBootEnable': 1,
                   'runtimeSecureBoot': 'UNPROVEN', 'runtimeSetupMode': 'UNPROVEN',
                   'originalAuthenticationTimestamps': 'NOT_EXPORTED_BY_VMGS',
                   'bootAuthorized': False}
        fd = os.open('manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=outputfd)
        with os.fdopen(fd, 'w') as stream:
            json.dump(receipt, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
        os.fsync(outputfd)
        return receipt
    finally:
        if outputfd is not None:
            os.close(outputfd)
        os.close(parentfd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('vmgs', 'code', 'template', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.vmgs, args.code, args.template, args.destination), sort_keys=True))
