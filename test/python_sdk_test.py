import hashlib
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

CODE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)

from sdk.python import (
    ARBITRUM_ONE_CHAIN_ID,
    Ap2Mandate,
    MandateVaultAgent,
    compute_mandate_digest,
    fetch_arbitrum_one_live_metrics,
    keccak256,
)


class _X402LocalProviderHandler(BaseHTTPRequestHandler):
    valid_body = b'{"signal":"LONG_ARB_USDC_YIELD","confidence":0.99}'
    corrupt_body = b'{"signal":"CORRUPTED_TAMPERED_PAYLOAD"}'

    def log_message(self, format, *args):
        return

    def do_GET(self):
        proof_raw = self.headers.get("x-payment-proof")
        is_corrupt = "corrupt=1" in self.path
        expected_sha = "0x" + hashlib.sha256(self.valid_body).hexdigest()

        if not proof_raw:
            challenge = {
                "x402Version": 1,
                "scheme": "mandatevault-arbitrum-usdc",
                "chainId": ARBITRUM_ONE_CHAIN_ID,
                "vaultCompatible": True,
                "paymentNonce": "0x" + ("ab" * 32),
                "provider": "0x1111111111111111111111111111111111118004",
                "amountUsdc": "6000000" if is_corrupt else "250000",
                "resourceUri": self.path,
                "resourceHash": "0x" + keccak256(self.path.encode()).hex(),
                "categoryHash": "0x" + ("cd" * 32),
                "expectedPayloadHash": expected_sha,
                "forceEscrow": is_corrupt,
            }
            raw_json = json.dumps(challenge)
            self.send_response(402)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Payment-Required", raw_json)
            self.end_headers()
            self.wfile.write(json.dumps({"challenge": challenge}).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.corrupt_body if is_corrupt else self.valid_body)


class MandateVaultPythonSdkTests(unittest.TestCase):
    def test_01_keccak256_and_eip712_digest_vectors(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak256(b"transfer(address,uint256)")[:4].hex(),
            "a9059cbb",
        )

        mandate = Ap2Mandate(
            mandate_id="0x" + ("11" * 32),
            agent="0x2222222222222222222222222222222222222222",
            max_per_tx=10_000_000,
            max_rolling_24h=50_000_000,
            valid_after=1_760_000_000,
            deadline=1_900_000_000,
            min_provider_reputation_bps=8000,
            allowed_providers_root="0x" + ("00" * 32),
            escrow_threshold=5_000_000,
            dispute_window_seconds=1800,
        )
        digest = compute_mandate_digest(
            ARBITRUM_ONE_CHAIN_ID,
            "0x4242424242424242424242424242424242424242",
            mandate,
        )
        self.assertTrue(digest.startswith("0x") and len(digest) == 66)

    def test_02_http_x402_roundtrip_and_sha256_dispute_freeze(self):
        server = HTTPServer(("127.0.0.1", 0), _X402LocalProviderHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            mandate = Ap2Mandate(
                mandate_id="0x" + ("aa" * 32),
                agent="0x3333333333333333333333333333333333333333",
                max_per_tx=10_000_000,
                max_rolling_24h=50_000_000,
                valid_after=1_760_000_000,
                deadline=1_900_000_000,
                min_provider_reputation_bps=8000,
                allowed_providers_root="0x" + ("00" * 32),
                escrow_threshold=5_000_000,
                dispute_window_seconds=1800,
            )

            disputes = []

            def settle_cb(ctx):
                is_escrow = int(ctx["challenge"]["amountUsdc"]) >= 5_000_000
                return {
                    "txHash": "0x" + ("77" * 32),
                    "escrowId": "1" if is_escrow else "0",
                }

            agent = MandateVaultAgent(
                vault_address="0x4242424242424242424242424242424242424242",
                mandate=mandate,
                mandate_signature="0x" + ("55" * 65),
                settlement_callback=settle_cb,
                dispute_callback=lambda d: disputes.append(d),
            )

            # Normal 0.25 USDC x402 call
            ok_res = agent.request(f"http://127.0.0.1:{port}/signal")
            self.assertEqual(ok_res["status"], 200)
            self.assertTrue(ok_res["settled"])
            self.assertFalse(ok_res["disputeTriggered"])
            self.assertEqual(len(disputes), 0)

            # Corrupted 6.00 USDC x402 call -> triggers automatic dispute freeze callback
            bad_res = agent.request(f"http://127.0.0.1:{port}/signal?corrupt=1")
            self.assertEqual(bad_res["status"], 200)
            self.assertTrue(bad_res["disputeTriggered"])
            self.assertEqual(len(disputes), 1)
            self.assertEqual(disputes[0]["escrowId"], 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_03_live_arbitrum_one_rpc_metrics(self):
        live = fetch_arbitrum_one_live_metrics("https://arb1.arbitrum.io/rpc")
        self.assertEqual(live["chainId"], 42161)
        self.assertGreater(live["blockNumber"], 400_000_000)
        self.assertEqual(
            live["aTokenAddress"].lower(),
            "0x724dc807b04555b71ed48a6896b6f41593b8c637",
        )
        self.assertGreater(live["supplyAprPercent"], 0.0)


if __name__ == "__main__":
    unittest.main()
