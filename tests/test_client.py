"""Sync + async client integration tests against a mocked staging API."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from deepidv_chain import (
    AsyncClient,
    Client,
    DeepidvAuthError,
    DeepidvNotFoundError,
    DeepidvRateLimitError,
)
from deepidv_chain._internal.http import iter_sse_blocks, parse_sse_block

STAGING = "https://staging-api.deepidv.com"

ATTESTATION_FIXTURE = {
    "attestation_id": "attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V",
    "record_type": "IDV",
    "issuer_id": "iss_acme_prod",
    "segment_id": "seg_acme_2026q2",
    "leaf_index": 17,
    "tree_size_at_inclusion": 18,
    "issued_at": "2026-04-01T12:34:56.789Z",
    "labels": [{"name": "Country", "value": "USA"}],
    "envelope": {
        "schema_version": "envelope/v1",
        "attestation_id": "attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V",
        "record_type": "IDV",
        "issuer_id": "iss_acme_prod",
        "subject_pseudonym": "sha256:" + "a" * 64,
        "issued_at": "2026-04-01T12:34:56.789Z",
        "claim_hash": "sha256:" + "b" * 64,
        "labels": [{"name": "Country", "value": "USA"}],
        "salt": "5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
        "extensions": {},
    },
    "inclusion_proof": {
        "leaf_index": 17,
        "tree_size": 18,
        "audit_path": [],
    },
    "sth": {
        "schema_version": "sth/v1",
        "segment_id": "seg_acme_2026q2",
        "tree_size": 18,
        "root_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-01T13:00:00.000Z",
        "signer_key_id": "kms-alias/chain-master-prod",
        "signature": "MEUCIA==",
    },
    "revoked": False,
}


@respx.mock
def test_get_attestation_sync():
    route = respx.get(
        f"{STAGING}/v1/attestations/attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V"
    ).mock(return_value=httpx.Response(200, json=ATTESTATION_FIXTURE))

    with Client(STAGING) as client:
        attestation = client.get_attestation("attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V")
    assert route.called
    assert attestation.attestation_id == "attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V"
    assert attestation.record_type == "IDV"


@respx.mock
def test_list_registry_passes_params_and_cursor():
    page = {
        "items": [
            {
                "attestation_id": "attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V",
                "record_type": "IDV",
                "issuer_id": "iss_acme_prod",
                "issued_at": "2026-04-01T12:34:56.789Z",
                "labels": [],
                "revoked": False,
            }
        ],
        "next_cursor": "cur_xyz",
        "page_size": 1,
    }
    route = respx.get(f"{STAGING}/v1/registry").mock(
        return_value=httpx.Response(200, json=page)
    )
    with Client(STAGING) as client:
        result = client.list_registry({"record_type": "IDV", "revoked": False}, cursor="cur_abc")
    request = route.calls.last.request
    assert request.url.params["record_type"] == "IDV"
    assert request.url.params["revoked"] == "false"
    assert request.url.params["cursor"] == "cur_abc"
    assert result.next_cursor == "cur_xyz"
    assert len(result.items) == 1


@respx.mock
def test_404_maps_to_not_found():
    respx.get(f"{STAGING}/v1/attestations/missing").mock(
        return_value=httpx.Response(404, json={"message": "no such attestation"})
    )
    with Client(STAGING) as client, pytest.raises(DeepidvNotFoundError) as exc:
        client.get_attestation("missing")
    assert exc.value.status_code == 404
    assert "no such attestation" in str(exc.value)


@respx.mock
def test_401_maps_to_auth_error():
    respx.get(f"{STAGING}/v1/registry").mock(
        return_value=httpx.Response(401, json={"message": "bad token"})
    )
    with Client(STAGING, api_key="dpiv_live_bad") as client, pytest.raises(DeepidvAuthError):
        client.list_registry()


@respx.mock
def test_429_carries_retry_after():
    respx.get(f"{STAGING}/v1/registry").mock(
        return_value=httpx.Response(
            429,
            headers={"retry-after": "12"},
            json={"message": "slow down"},
        )
    )
    with Client(STAGING) as client, pytest.raises(DeepidvRateLimitError) as exc:
        client.list_registry()
    assert exc.value.retry_after_seconds == 12.0


@respx.mock
def test_download_bundle_returns_bytes():
    payload = b"PK\x03\x04fake-zip-bytes"
    respx.get(f"{STAGING}/v1/attestations/attest_X/bundle").mock(
        return_value=httpx.Response(200, content=payload)
    )
    with Client(STAGING) as client:
        data = client.download_bundle("attest_X")
    assert data == payload


@pytest.mark.asyncio
@respx.mock
async def test_async_get_attestation():
    respx.get(
        f"{STAGING}/v1/attestations/attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V"
    ).mock(return_value=httpx.Response(200, json=ATTESTATION_FIXTURE))
    async with AsyncClient(STAGING) as client:
        attestation = await client.get_attestation("attest_01J9X9YQ7W7N2T0M5K8P3R4Q6V")
    assert attestation.issuer_id == "iss_acme_prod"


def test_parse_sse_block_strips_optional_space():
    block = "event: attestation.minted\nid: 42\ndata: {\"hello\":\"world\"}"
    parsed = parse_sse_block(block)
    assert parsed == {"event": "attestation.minted", "id": "42", "data": '{"hello":"world"}'}


def test_parse_sse_block_drops_comment_lines():
    block = ":heartbeat\nevent: heartbeat\ndata: {}"
    parsed = parse_sse_block(block)
    assert parsed["event"] == "heartbeat"


def test_iter_sse_blocks_groups_by_blank():
    lines = ["event: a", "data: 1", "", "event: b", "data: 2", ""]
    out = list(iter_sse_blocks(iter(lines)))
    assert len(out) == 2


def test_authorization_header_set_when_api_key_present():
    with Client(STAGING, api_key="dpiv_live_abc") as client:
        assert client.headers["authorization"] == "Bearer dpiv_live_abc"


def test_no_authorization_header_when_no_api_key():
    with Client(STAGING) as client:
        assert "authorization" not in client.headers
