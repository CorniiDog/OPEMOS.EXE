"""One bounded descriptor reader for pinned operational code and JSON receipts.

Callers execute or parse the returned bytes, never reopen the path after hashing.
This grants no runtime, source ownership, or process-release authority.
"""
import base64
import hashlib
import os
import stat

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
UNPINNED = object()

class SourceReadFailure(ValueError):
    def __init__(self, evidence):
        self.evidence = evidence
        first = evidence['firstFailure']
        super().__init__(first['type'] + ': ' + first['reason'])

def identity(value):
    return {key: getattr(value, key) for key in FIELDS}

def read_verified(path, cap, expected_sha=UNPINNED, expected_size=None, uid=None):
    if type(cap) is not int or cap < 1:
        raise ValueError('positive integer read cap required')
    if expected_sha is not UNPINNED and (type(expected_sha) is not str or len(expected_sha) != 64
                                       or any(c not in '0123456789abcdef' for c in expected_sha)):
        raise ValueError('explicit expected source SHA must be 64 lowercase hex digits')
    if expected_size is not None and (type(expected_size) is not int or not 0 <= expected_size <= cap):
        raise ValueError('expected size outside cap')
    data = bytearray()
    digest = hashlib.sha256()
    evidence = {'path': str(path), 'cap': cap, 'readBoundIncludingOverflowSentinel': cap + 1,
                'observedBytes': 0, 'observedSHA256': digest.hexdigest(), 'prefixBase64': '',
                'EOF': False, 'before': None, 'after': None, 'pathAfter': None,
                'firstFailure': None, 'closeOutcomes': [], 'operationOrReleaseAuthorized': False}
    fd = None
    primary = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        evidence['before'] = identity(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('regular single-link source required')
        if uid is not None and before.st_uid != uid:
            raise ValueError('source owner mismatch')
        if before.st_size > cap:
            raise ValueError('source metadata exceeds cap')
        if expected_size is not None and before.st_size != expected_size:
            raise ValueError('source metadata differs from pinned size')
        while True:
            block = os.read(fd, min(65536, cap + 1 - len(data)))
            if not block:
                evidence['EOF'] = True
                break
            data.extend(block)
            digest.update(block)
            evidence.update(observedBytes=len(data), observedSHA256=digest.hexdigest(),
                            prefixBase64=base64.b64encode(data[:128]).decode())
            if len(data) > cap:
                raise ValueError('source stream exceeds cap')
        evidence['after'] = identity(os.fstat(fd))
        evidence['pathAfter'] = identity(os.lstat(path))
        if not evidence['before'] == evidence['after'] == evidence['pathAfter']:
            raise ValueError('source descriptor or path identity changed')
        if len(data) != before.st_size:
            raise ValueError('source length differs from descriptor metadata')
        if expected_sha is not UNPINNED and digest.hexdigest() != expected_sha:
            raise ValueError('source hash mismatch')
    except BaseException as error:
        primary = error
        evidence['firstFailure'] = {'type': type(error).__name__, 'reason': str(error)}
    finally:
        if fd is not None:
            try:
                os.close(fd)
                evidence['closeOutcomes'].append({'fd': fd, 'closed': True, 'UNKNOWN': False})
            except BaseException as error:
                evidence['closeOutcomes'].append({'fd': fd, 'closed': False, 'UNKNOWN': True,
                                                  'failure': type(error).__name__ + ': ' + str(error)})
                if primary is None:
                    primary = error
                    evidence['firstFailure'] = {'type': type(error).__name__, 'reason': str(error)}
    if primary is not None:
        raise SourceReadFailure(evidence) from primary
    pin = {'path': str(path), 'bytes': len(data), 'sha256': digest.hexdigest(),
           'identity': evidence['before']}
    return pin, bytes(data)

def verified_namespace(raw, filename, name, dependencies=None):
    """Execute verified bytes; declared local dependencies bypass path/cache imports."""
    import builtins
    namespace={'__name__':name,'__file__':str(filename)}
    if dependencies:
        normal=builtins.__import__
        def importer(module,globals=None,locals=None,fromlist=(),level=0):
            if level==0 and module in dependencies:return dependencies[module]
            return normal(module,globals,locals,fromlist,level)
        namespace['__builtins__']={**vars(builtins),'__import__':importer}
    exec(compile(raw,str(filename),'exec'),namespace)
    return namespace
