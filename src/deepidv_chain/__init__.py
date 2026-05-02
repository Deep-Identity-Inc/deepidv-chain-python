"""deepidv-chain — Python SDK for the deepidv chain layer.

Public surface (top level re-exports):

    from deepidv_chain import (
        Client,
        AsyncClient,
        verify_bundle,
        VerifyResult,
        VerifyCheck,
        DeepidvApiError,
        DeepidvAuthError,
        DeepidvNotFoundError,
        DeepidvRateLimitError,
        DeepidvServerError,
    )

The chain layer is the verification engine and agentic compliance suite operated
by deepidv. Public surface: https://proof.deepidv.com.
"""

from deepidv_chain.client import AsyncClient, Client
from deepidv_chain.errors import (
    DeepidvApiError,
    DeepidvAuthError,
    DeepidvNotFoundError,
    DeepidvRateLimitError,
    DeepidvServerError,
)
from deepidv_chain.types import (
    AttestationDetail,
    BundleManifest,
    ConsistencyProof,
    EnvelopeV1,
    IssuerProfile,
    LogView,
    RegistryPage,
    SegmentProfile,
    StreamEvent,
    Sth,
    VerifyCheck,
    VerifyResult,
)
from deepidv_chain.verify import verify_bundle

__version__ = "1.0.0"

__all__ = [
    "AsyncClient",
    "AttestationDetail",
    "BundleManifest",
    "Client",
    "ConsistencyProof",
    "DeepidvApiError",
    "DeepidvAuthError",
    "DeepidvNotFoundError",
    "DeepidvRateLimitError",
    "DeepidvServerError",
    "EnvelopeV1",
    "IssuerProfile",
    "LogView",
    "RegistryPage",
    "SegmentProfile",
    "StreamEvent",
    "Sth",
    "VerifyCheck",
    "VerifyResult",
    "__version__",
    "verify_bundle",
]
