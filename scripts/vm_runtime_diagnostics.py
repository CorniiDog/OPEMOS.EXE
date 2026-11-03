"""Optional observation copies and truthful completion for Linux VM adapters.

The staged adapters embed these exact function bodies. They grant no runtime
or resource authority: authenticated native proof, source/FD ownership,
canonical state, resource admission and cleanup remain with callers. Private
machine identities, grants and historical receipts are not repository inputs.
"""
from contextlib import contextmanager


def capture_observation(captures, record):
    """Keep bounded optional copies without turning a full sink into a veto."""
    if type(captures) is list and len(captures) < 32:
        captures.append(record)


@contextmanager
def readonly_observer_phase(db, backend):
    """Keep report copies outside the native proof and exception contract."""
    try:
        yield
    except BaseException as error:
        if getattr(backend, 'observer_first_failure', None) is None:
            backend.observer_first_failure = getattr(error, 'readonlyObserverFailure', {
                'type': type(error).__name__, 'reason': str(error),
                'evidence': getattr(error, 'evidence', None),
            })
        raise
    finally:
        backend.observer_captures = []
        backend.observer_capture_receipt = None


@contextmanager
def readonly_observer_transaction(root, db, backend):
    """Keep report copies outside the native proof and exception contract."""
    try:
        yield
    except BaseException as error:
        if getattr(backend, 'observer_first_failure', None) is None:
            backend.observer_first_failure = getattr(error, 'readonlyObserverFailure', {
                'type': type(error).__name__, 'reason': str(error),
                'evidence': getattr(error, 'evidence', None),
            })
        raise
    finally:
        backend.observer_captures = []
        backend.observer_capture_receipt = None


def operational_complete(result, fds_closed):
    """A closed installer observation can succeed without full installation."""
    closure = result.get('closure', {})
    return bool(
        fds_closed is True
        and result.get('MODEL_ONLY') is False
        and result.get('first') is None
        and result.get('runtimeAuthorized') is True
        and result.get('leaseMustRemainHeld') is False
        and closure.get('known') is True
        and closure.get('FDsClosed') is True
        and closure.get('logicalLeaseClosed') is True
        and (result.get('accepted') is True
             or result.get('installerDiagnosticComplete') is True)
    )
