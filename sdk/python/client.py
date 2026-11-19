"""
MandateVault Python Agent SDK (`code/sdk/python/client.py`)
-----------------------------------------------------------
Enables any Python AI Agent (LangChain, AutoGen, CrewAI, MCP) to integrate
Arbitrum One `MandateVault` in 3 lines of code:
  1. Computes byte-exact EIP-712 AP2 Mandate digests matching `MandateVault.sol`
  2. Automatically intercepts HTTP `402 Payment Required` responses, settles on-chain,
     verifies SHA-256 payload integrity (triggering Dispute Timelock freeze on mismatch),
     and retries with `X-Payment-Proof`.
  3. Reads live Arbitrum One (`https://arb1.arbitrum.io/rpc`) block & Aave V3 USDC yield telemetry.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

ARBITRUM_ONE_CHAIN_ID = 42161
ARBITRUM_ONE_RPC = "https://arb1.arbitrum.io/rpc"
ARBITRUM_ONE_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
ARBITRUM_ONE_AAVE_V3_POOL = "0x794a61358D6845594F94dc1DB02A252b5b4814aD"
ARBITRUM_ONE_AARB_USDCN = "0x724dc807b04555b71ed48a6896b6f41593b8c637"

# ---------------------------------------------------------------------------
# Pure-Python FIPS-202 Keccak-256 (Ethereum / Arbitrum EIP-712 Standard)
# ---------------------------------------------------------------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_MASK64 = (1 << 64) - 1


def _rotl64(val: int, shift: int) -> int:
    return ((val << shift) | (val >> (64 - shift))) & _MASK64


def _keccak_f1600(st: list[int]) -> None:
    bc = [0] * 5
    for r in range(24):
        for i in range(5):
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rotl64(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                st[j + i] ^= t
        t = st[1]
        for i in range(24):
            j = _PILN[i]
            bc[0] = st[j]
            st[j] = _rotl64(t, _ROTC[i])
            t = bc[0]
        for j in range(0, 25, 5):
            for i in range(5):
                bc[i] = st[j + i]
            for i in range(5):
                st[j + i] ^= ((~bc[(i + 1) % 5]) & _MASK64) & bc[(i + 2) % 5]
        st[0] ^= _RC[r]


def keccak256(data: bytes) -> bytes:
    """Computes standard Ethereum Keccak-256 digest (0x01 padding, 136-byte rate)."""
    st = [0] * 25
    rate = 136
    offset = 0
    while offset + rate <= len(data):
        for i in range(17):
            lane = int.from_bytes(data[offset + i * 8 : offset + (i + 1) * 8], "little")
            st[i] ^= lane
        _keccak_f1600(st)
        offset += rate

    block = bytearray(136)
    rem = len(data) - offset
    block[:rem] = data[offset:]
    block[rem] ^= 0x01
    block[rate - 1] ^= 0x80
    for i in range(17):
        lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        st[i] ^= lane
    _keccak_f1600(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))


def _hex_to_bytes32(h: str) -> bytes:
    raw = bytes.fromhex(h[2:] if h.startswith("0x") else h)
    if len(raw) != 32:
        raise ValueError(f"Expected 32-byte hex value, got {len(raw)} bytes")
    return raw


def _addr_to_word(addr: str) -> bytes:
    raw = bytes.fromhex(addr[2:] if addr.startswith("0x") else addr)
    if len(raw) != 20:
        raise ValueError(f"Expected 20-byte Ethereum address, got {len(raw)} bytes")
    return b"\x00" * 12 + raw


def _uint_to_word(val: int) -> bytes:
    return int(val).to_bytes(32, "big")


@dataclass(frozen=True)
class Ap2Mandate:
    mandate_id: str
    agent: str
    max_per_tx: int
    max_rolling_24h: int
    valid_after: int
    deadline: int
    min_provider_reputation_bps: int
    allowed_providers_root: str
    escrow_threshold: int
    dispute_window_seconds: int
    verifier_override: str = "0x0000000000000000000000000000000000000000"


def hash_mandate_struct(mandate: Ap2Mandate) -> bytes:
    type_str = (
        b"Mandate(bytes32 mandateId,address agent,uint256 maxPerTx,uint256 maxRolling24h,"
        b"uint64 validAfter,uint64 deadline,uint16 minProviderReputationBps,"
        b"bytes32 allowedProvidersRoot,uint256 escrowThreshold,uint64 disputeWindowSeconds,"
        b"address verifierOverride)"
    )
    encoded = b"".join(
        [
            keccak256(type_str),
            _hex_to_bytes32(mandate.mandate_id),
            _addr_to_word(mandate.agent),
            _uint_to_word(mandate.max_per_tx),
            _uint_to_word(mandate.max_rolling_24h),
            _uint_to_word(mandate.valid_after),
            _uint_to_word(mandate.deadline),
            _uint_to_word(mandate.min_provider_reputation_bps),
            _hex_to_bytes32(mandate.allowed_providers_root),
            _uint_to_word(mandate.escrow_threshold),
            _uint_to_word(mandate.dispute_window_seconds),
            _addr_to_word(mandate.verifier_override),
        ]
    )
    return keccak256(encoded)


def compute_mandate_digest(chain_id: int, vault_address: str, mandate: Ap2Mandate) -> str:
    """Computes the exact EIP-712 digest (`0x` hex) matching `MandateVault.computeMandateDigest`."""
    domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    domain_separator = keccak256(
        b"".join(
            [
                domain_typehash,
                keccak256(b"MandateVault"),
                keccak256(b"1"),
                _uint_to_word(chain_id),
                _addr_to_word(vault_address),
            ]
        )
    )
    struct_hash = hash_mandate_struct(mandate)
    digest = keccak256(b"\x19\x01" + domain_separator + struct_hash)
    return "0x" + digest.hex()


class MandateVaultAgent:
    """3-Line AI Agent HTTP x402 Client backed by Arbitrum MandateVault."""

    def __init__(
        self,
        *,
        vault_address: str,
        mandate: Ap2Mandate,
        mandate_signature: str,
        settlement_callback: Callable[[Dict[str, Any]], Dict[str, Any]],
        dispute_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.vault_address = vault_address
        self.mandate = mandate
        self.mandate_signature = mandate_signature
        self.settlement_callback = settlement_callback
        self.dispute_callback = dispute_callback

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        req_headers = {"User-Agent": "MandateVault-Python-SDK/1.0", **(headers or {})}
        req = urllib.request.Request(url, method=method, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")
                return {"status": resp.status, "settled": False, "body": body}
        except urllib.error.HTTPError as err:
            if err.code != 402:
                raise
            header_raw = err.headers.get("x-payment-required")
            if header_raw:
                challenge = json.loads(header_raw)
            else:
                challenge = json.loads(err.read().decode("utf-8"))["challenge"]

        amount = int(challenge["amountUsdc"])
        if amount > self.mandate.max_per_tx:
            raise PermissionError(
                f"AP2 Mandate max_per_tx ({self.mandate.max_per_tx}) exceeded by x402 challenge ({amount})"
            )

        settlement = self.settlement_callback(
            {
                "vaultAddress": self.vault_address,
                "mandate": self.mandate,
                "mandateSignature": self.mandate_signature,
                "challenge": challenge,
            }
        )

        proof = {
            "paymentNonce": challenge["paymentNonce"],
            "mandateId": self.mandate.mandate_id,
            "agent": self.mandate.agent,
            "provider": challenge["provider"],
            "amountUsdc": str(amount),
            "txHash": settlement["txHash"],
            "escrowId": str(settlement.get("escrowId", "0")),
        }

        retry_headers = {**req_headers, "x-payment-proof": json.dumps(proof)}
        retry_req = urllib.request.Request(url, method=method, headers=retry_headers)
        with urllib.request.urlopen(retry_req, timeout=10) as unlocked:
            raw_bytes = unlocked.read()
            text = raw_bytes.decode("utf-8")

        dispute_triggered = False
        expected_hash = challenge.get("expectedPayloadHash", "")
        zero_h = "0x" + ("0" * 64)
        if expected_hash and expected_hash != zero_h and int(proof["escrowId"]) > 0:
            observed_hash = "0x" + hashlib.sha256(raw_bytes).hexdigest()
            if observed_hash.lower() != expected_hash.lower():
                dispute_triggered = True
                if self.dispute_callback is not None:
                    self.dispute_callback(
                        {
                            "escrowId": int(proof["escrowId"]),
                            "expectedPayloadHash": expected_hash,
                            "observedPayloadHash": observed_hash,
                            "reason": "SHA256_PAYLOAD_MISMATCH",
                        }
                    )

        return {
            "status": unlocked.status,
            "settled": True,
            "proof": proof,
            "disputeTriggered": dispute_triggered,
            "body": text,
        }


def fetch_arbitrum_one_live_metrics(rpc_url: str = ARBITRUM_ONE_RPC) -> Dict[str, Any]:
    """Queries live Arbitrum One block height and Aave V3 Native USDC reserve rates."""
    padded_usdc = ARBITRUM_ONE_USDC[2:].lower().rjust(64, "0")
    padded_atoken = ARBITRUM_ONE_AARB_USDCN[2:].lower().rjust(64, "0")

    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_call",
            "params": [{"to": ARBITRUM_ONE_AAVE_V3_POOL, "data": f"0x35ea6a75{padded_usdc}"}, "latest"],
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_call",
            "params": [{"to": ARBITRUM_ONE_AARB_USDCN, "data": "0x18160ddd"}, "latest"],
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_call",
            "params": [{"to": ARBITRUM_ONE_USDC, "data": f"0x70a08231{padded_atoken}"}, "latest"],
        },
    ]

    req = urllib.request.Request(
        rpc_url,
        data=json.dumps(batch).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "MandateVault-Python-SDK/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        items = json.loads(resp.read().decode("utf-8"))

    by_id = {item["id"]: item["result"] for item in items}
    block_num = int(by_id[1], 16)
    r_hex = by_id[2][2:]
    liquidity_index = int(r_hex[64:128], 16)
    liquidity_rate = int(r_hex[128:192], 16)
    atoken_addr = "0x" + r_hex[8 * 64 + 24 : 9 * 64]
    atoken_supply_usdc = int(by_id[3], 16) / 1e6
    pool_cash_usdc = int(by_id[4], 16) / 1e6
    apr_pct = (liquidity_rate / 1e27) * 100.0

    return {
        "chainId": ARBITRUM_ONE_CHAIN_ID,
        "blockNumber": block_num,
        "usdcAddress": ARBITRUM_ONE_USDC,
        "aavePoolAddress": ARBITRUM_ONE_AAVE_V3_POOL,
        "aTokenAddress": atoken_addr,
        "liquidityIndexRay": str(liquidity_index),
        "currentLiquidityRateRay": str(liquidity_rate),
        "supplyAprPercent": round(apr_pct, 4),
        "aArbUsdcTotalSupplyUsdc": round(atoken_supply_usdc, 2),
        "poolAvailableCashUsdc": round(pool_cash_usdc, 2),
    }
