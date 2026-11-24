"""totum_verify — hermetic verifier for the Totum audit chain and receipts.

Public API:
    >>> from totum_verify import verify_chain, verify_receipt
    >>> result = verify_chain(...)
    >>> print(result["ok"], result["length"])

The verifier reimplements the chain hash + Ed25519 signature primitives over
stdlib + `cryptography`. Zero Totum-internal imports. Clone-and-run for
external auditors.

CLI:
    $ totum-verify --remote https://totum.run
    $ totum-verify --receipt receipt.json --remote https://totum.run
"""

from totum_verify._verifier import RemoteFetchError, verify_chain, verify_receipt

__version__ = "0.2.2"
__all__ = ["RemoteFetchError", "verify_chain", "verify_receipt", "__version__"]
