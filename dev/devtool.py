"""Operator tool for the RillSwap regtest dev stack (dev/compose.yaml).

Runs inside the rillswap-dev image. `bootstrap` is idempotent: every step
checks current state before acting, so rerunning it after a restart or an
interrupted attempt only completes what is missing. All state lives under
/state (a named Docker volume) and is disposable regtest data.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx

STATE = Path(os.environ.get("RILL_DEV_STATE", "/state"))
SRC = Path(os.environ.get("RILL_DEV_SRC", "/src"))
CRYPTO = os.environ.get("RILL_CRYPTO_LIBRARY", "/opt/rill/native/librill_crypto.so")
NETWORK_FIXTURE = SRC / "rill-provider/tests/fixtures/initial-btc-to-ln-v1.json"

CORE_URL = "http://bitcoind:18443"
CORE_AUTH = ("rill", "rill-dev-regtest")
# Matches the static `-rpcauth=__cookie__:...` entry in compose.yaml, so the
# cookie file Rill reads stays valid across bitcoind restarts.
CORE_COOKIE = "__cookie__:rill-dev-regtest-cookie\n"
LOCAL_CORE_PORT = 18443
LOCAL_LND_PORT = 10009

RELAY_INTERNAL = os.environ.get("RILL_DEV_RELAY_INTERNAL", "ws://relay:8080")
RELAY_HOST = os.environ.get("RILL_DEV_RELAY_HOST", "ws://127.0.0.1:7777")

LND_NODES = ("maker", "user", "merchant")
FUNDED_LND = ("maker", "user")
# maker -> user: BTC->LN payouts to the user. user -> maker: the user pays the
# maker's LN->BTC hold invoices. maker -> merchant: payments to the shop.
CHANNELS = (("maker", "user"), ("user", "maker"), ("maker", "merchant"))
MERCHANT_ORIGIN = "https://shop.rillswap.test"
MERCHANT_DIR = STATE / "merchant"
SHOP_URL = os.environ.get("RILL_DEV_SHOP_INTERNAL", "http://shop:8090")
DIRECTIONS = ("btc-to-ln", "ln-to-btc")
EVM_DIRECTIONS = ("erc20-to-ln", "ln-to-erc20")  # RS-010 makers on the Anvil chain
CHANNEL_SAT = 5_000_000
LND_FUND_BTC = 10
CORE_FUND_BTC = 10
MATURE_HEIGHT = 150
# LND (bitcoind backend) reports synced_to_chain only within two hours of the
# tip's timestamp; refresh well inside that so a persisted chain can resync.
STALE_TIP_SECONDS = 3600
MONEROD_URL = "http://monerod:18081"
MONERO_WALLETS = ("merchant", "buyer")
MONERO_WALLET_DIRS = Path(os.environ.get("RILL_DEV_MONERO_WALLETS", "/monero-wallets"))
# 100 coinbase outputs give the buyer spendable funds (60-block unlock) and
# enough decoys for ring size 16, as in upstream's wallet transfer tests.
MONERO_MATURE_HEIGHT = 130
PICONERO = 10**12


def log(message: str) -> None:
    print(f"[devtool {time.strftime('%H:%M:%S')}] {message}", flush=True)


def private_write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data.encode() if isinstance(data, str) else data)
    tmp.chmod(mode)
    tmp.replace(path)


def wait_for(what: str, check: Any, timeout: float = 120, interval: float = 1) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = check()
        except (httpx.HTTPError, RpcError):
            result = None
        if result:
            return result
        if time.monotonic() > deadline:
            raise SystemExit(f"timed out waiting for {what}")
        time.sleep(interval)


class RpcError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class Core:
    """Bitcoin Core JSON-RPC over the compose network (rpcauth user)."""

    def __init__(self, wallet: str | None = None) -> None:
        self.wallet = wallet

    def __call__(self, method: str, *params: Any) -> Any:
        path = f"/wallet/{self.wallet}" if self.wallet else "/"
        body = {"jsonrpc": "1.0", "id": "dev", "method": method, "params": list(params)}
        response = httpx.post(CORE_URL + path, json=body, auth=CORE_AUTH, timeout=120)
        payload = response.json()
        if payload.get("error"):
            raise RpcError(payload["error"]["code"], payload["error"]["message"])
        return payload["result"]


class Lnd:
    """LND REST client using credentials copied to /state/lnd/<node>."""

    def __init__(self, node: str) -> None:
        self.node = node
        creds = STATE / "lnd" / node
        macaroon = (creds / "admin.macaroon").read_bytes().hex()
        self.client = httpx.Client(
            base_url=f"https://lnd-{node}:8080",
            verify=str(creds / "tls.cert"),
            headers={"Grpc-Metadata-macaroon": macaroon},
            timeout=120,
        )

    def get(self, path: str, **params: Any) -> Any:
        response = self.client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def post(self, path: str, body: dict[str, Any]) -> Any:
        response = self.client.post(path, json=body)
        if response.status_code >= 400:
            raise SystemExit(f"lnd-{self.node} {path}: {response.text}")
        return response.json()

    def info(self) -> dict[str, Any]:
        return self.get("/v1/getinfo")

    def pubkey(self) -> str:
        return self.info()["identity_pubkey"]

    def new_address(self) -> str:
        return self.get("/v1/newaddress", type="TAPROOT_PUBKEY")["address"]

    def onchain_sat(self) -> int:
        return int(self.get("/v1/balance/blockchain").get("confirmed_balance", 0))

    def channels(self) -> list[dict[str, Any]]:
        return self.get("/v1/channels").get("channels", [])

    def pending_open(self) -> list[dict[str, Any]]:
        return self.get("/v1/channels/pending").get("pending_open_channels", [])

    def add_invoice(self, sat: int, memo: str) -> str:
        return self.post("/v1/invoices", {"value": str(sat), "memo": memo})["payment_request"]

    def pay(self, bolt11: str) -> dict[str, Any]:
        """Pay via routerrpc SendPaymentV2 (a stream of payment updates)."""
        body = {"payment_request": bolt11, "timeout_seconds": 60, "fee_limit_sat": "1000"}
        last: dict[str, Any] = {}
        with self.client.stream("POST", "/v2/router/send", json=body) as response:
            for line in response.iter_lines():
                if not line.strip():
                    continue
                update = json.loads(line)
                if "error" in update:
                    raise SystemExit(f"lnd-{self.node} payment error: {update['error']}")
                last = update.get("result", update)
                if last.get("status") in ("SUCCEEDED", "FAILED"):
                    break
        return last


class MoneroDaemon:
    def __call__(self, method: str, **params: Any) -> Any:
        response = httpx.post(
            f"{MONEROD_URL}/json_rpc",
            json={"jsonrpc": "2.0", "id": 0, "method": method, "params": params},
            timeout=60,
        )
        response.raise_for_status()
        body = response.json()
        if "error" in body:
            raise RpcError(body["error"]["code"], body["error"]["message"])
        return body["result"]

    def height(self) -> int:
        return int(self("get_info")["height"])

    def mine(self, blocks: int, address: str) -> int:
        return int(
            self("generateblocks", amount_of_blocks=blocks, wallet_address=address)["height"]
        )


class MoneroWallet:
    """monero-wallet-rpc for one wallet (the dev wallets have no password)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.url = f"http://monero-wallet-{name}:18082/json_rpc"

    def raw(self, method: str, **params: Any) -> Any:
        response = httpx.post(
            self.url,
            json={"jsonrpc": "2.0", "id": 0, "method": method, "params": params},
            timeout=120,
        )
        response.raise_for_status()
        body = response.json()
        if "error" in body:
            raise RpcError(body["error"]["code"], body["error"]["message"])
        return body["result"]

    def __call__(self, method: str, **params: Any) -> Any:
        try:
            return self.raw(method, **params)
        except RpcError as error:
            if error.code != -13:  # no wallet open (e.g. wallet-rpc restarted)
                raise
        self.raw("open_wallet", filename=self.name, password="")
        return self.raw(method, **params)

    def address(self) -> str:
        return self("get_address", account_index=0)["address"]

    def balance(self) -> dict[str, float]:
        self("refresh")
        result = self("get_balance", account_index=0)
        return {
            "balance_xmr": result["balance"] / PICONERO,
            "unlocked_xmr": result["unlocked_balance"] / PICONERO,
        }


def ensure_monero_wallet(name: str) -> MoneroWallet:
    """Open the wallet; create it only in an empty wallet volume (read-only mounted here)."""
    wallet = MoneroWallet(name)
    directory = MONERO_WALLET_DIRS / name
    if not directory.is_dir():
        raise SystemExit(
            f"{directory} is not mounted; cannot tell whether the {name} wallet exists"
        )
    if any(directory.iterdir()):
        wallet.raw("open_wallet", filename=name, password="")  # never replaced, even if broken
        return wallet
    # An empty merchant volume next to existing shop Monero state means the
    # wallet was lost, not that this is a fresh stack: never replace it.
    shop_state = STATE / "shop/monero"
    if name == "merchant" and shop_state.is_dir() and any(shop_state.iterdir()):
        raise SystemExit("Monero merchant wallet missing but the shop's Monero state exists; reset")
    log(f"creating Monero wallet {name}")
    wallet.raw("create_wallet", filename=name, password="", language="English")
    return wallet


def ensure_monero() -> dict[str, str]:
    daemon = MoneroDaemon()
    wait_for("monerod", lambda: daemon.height() > 0)
    wallets = {name: ensure_monero_wallet(name) for name in MONERO_WALLETS}
    addresses = {name: wallet.address() for name, wallet in wallets.items()}
    height = daemon.height()
    if height < MONERO_MATURE_HEIGHT:
        log(f"mining {MONERO_MATURE_HEIGHT - height} Monero blocks to the buyer")
        daemon.mine(MONERO_MATURE_HEIGHT - height, addresses["buyer"])
    for name, wallet in wallets.items():
        try:
            wallet("refresh")
        except RpcError as error:
            # e.g. "reorg exceeds maximum allowed depth" after the chain volume was wiped
            raise SystemExit(
                f"Monero {name} wallet does not match the chain ({error}); reset"
            ) from error
        wallet("store")
    return addresses


def copy_lnd_credentials(node: str) -> None:
    source = Path("/lnd") / node
    target = STATE / "lnd" / node
    wait_for(f"lnd-{node} credentials", lambda: (source / "tls.cert").exists(), timeout=60)
    private_write(target / "tls.cert", (source / "tls.cert").read_bytes(), 0o644)
    macaroon = source / "data/chain/bitcoin/regtest/admin.macaroon"
    wait_for(f"lnd-{node} macaroon", macaroon.exists, timeout=60)
    private_write(target / "admin.macaroon", macaroon.read_bytes())


def network_identity() -> dict[str, Any]:
    return json.loads(NETWORK_FIXTURE.read_text())["network_identity"]


def miner_address() -> str:
    path = STATE / "miner.address"
    if not path.exists():
        private_write(path, Core("miner")("getnewaddress", "", "bech32m"), 0o644)
    return path.read_text().strip()


def mine(blocks: int) -> int:
    Core()("generatetoaddress", blocks, miner_address())
    return Core()("getblockcount")


# --- bootstrap ---------------------------------------------------------------


def ensure_wallet(name: str) -> None:
    core = Core()
    if name in core("listwallets"):
        return
    try:
        core("loadwallet", name)
    except RpcError:
        core("createwallet", name)


def refresh_stale_tip() -> None:
    """Mine once if the chain tip is too old for LND to call itself synced.

    LND (bitcoind backend) only reports ``synced_to_chain`` when the best
    block is recent. A persisted regtest chain resumes with a stale tip, so
    without this LND would never report synced and the sync wait would hang.
    No-op on a freshly mined tip, so the normal bootstrap adds no extra block.
    """
    if time.time() - int(Core()("getblockchaininfo")["time"]) > STALE_TIP_SECONDS:
        log("refreshing a stale chain tip so LND can report synced")
        mine(1)


def wait_lnd_synced(nodes: list[Lnd]) -> None:
    refresh_stale_tip()

    def synced() -> bool:
        height = Core()("getblockcount")
        return all(
            (info := node.info())["synced_to_chain"] and int(info["block_height"]) == height
            for node in nodes
        )

    wait_for("LND chain sync", synced, timeout=180)


def ensure_chain_and_funds(lnds: dict[str, Lnd]) -> None:
    for wallet in ("miner", "user", "maker"):
        ensure_wallet(wallet)
    height = Core()("getblockcount")
    if height < MATURE_HEIGHT:
        log(f"mining {MATURE_HEIGHT - height} blocks for mature coins")
        mine(MATURE_HEIGHT - height)
    funded = False
    miner = Core("miner")
    for node in FUNDED_LND:
        lnd = lnds[node]
        # total_balance includes unconfirmed change from a pending channel open.
        if int(lnd.get("/v1/balance/blockchain").get("total_balance", 0)) < 100_000_000:
            log(f"funding lnd-{node} with {LND_FUND_BTC} BTC")
            miner("sendtoaddress", lnd.new_address(), LND_FUND_BTC)
            funded = True
    for wallet in ("user", "maker"):
        if Core(wallet)("getbalances")["mine"]["trusted"] < 1:
            log(f"funding Core wallet {wallet} with {CORE_FUND_BTC} BTC")
            address = Core(wallet)("getnewaddress", "", "bech32m")
            miner("sendtoaddress", address, CORE_FUND_BTC)
            funded = True
    if funded:
        mine(6)
    wait_lnd_synced(list(lnds.values()))
    for node in FUNDED_LND:
        lnd = lnds[node]
        wait_for(f"lnd-{node} confirmed funds", lambda lnd=lnd: lnd.onchain_sat() > 0, timeout=60)


def has_channel(local: Lnd, remote_pubkey: str) -> bool:
    """True when `local` opened (or is opening) a channel to `remote_pubkey`."""
    for channel in local.channels():
        if channel["remote_pubkey"] == remote_pubkey and channel.get("initiator"):
            return True
    for pending in local.pending_open():
        channel = pending["channel"]
        if channel["remote_node_pub"] == remote_pubkey and channel["initiator"] in (
            "INITIATOR_LOCAL",
            "INITIATOR_BOTH",
        ):
            return True
    return False


def ensure_peer(local: Lnd, remote_pubkey: str, remote_node: str) -> None:
    def connected() -> bool:
        return any(p["pub_key"] == remote_pubkey for p in local.get("/v1/peers").get("peers", []))

    if not connected():
        local.client.post(
            "/v1/peers",
            json={
                "addr": {"pubkey": remote_pubkey, "host": f"lnd-{remote_node}:9735"},
                "perm": True,
            },
        )
        wait_for(f"peer lnd-{remote_node}", connected)


def ensure_channels(lnds: dict[str, Lnd]) -> None:
    pubkeys = {node: lnd.pubkey() for node, lnd in lnds.items()}
    opened = False
    for local, remote in CHANNELS:
        if has_channel(lnds[local], pubkeys[remote]):
            continue
        ensure_peer(lnds[local], pubkeys[remote], remote)
        # LND refuses to open channels while it lags behind the chain tip.
        wait_lnd_synced(list(lnds.values()))
        log(f"opening {CHANNEL_SAT} sat channel {local} -> {remote}")
        lnds[local].post(
            "/v1/channels",
            {
                "node_pubkey": base64.b64encode(bytes.fromhex(pubkeys[remote])).decode(),
                "local_funding_amount": str(CHANNEL_SAT),
                "sat_per_vbyte": "2",
            },
        )
        # Confirm the funding change, so a second channel from the same node
        # can spend it (LND only funds from confirmed outputs).
        mine(1)
        opened = True
    if opened or any(lnd.pending_open() for lnd in lnds.values()):
        mine(6)

    def all_active() -> bool:
        for local, remote in CHANNELS:
            if not any(
                c["remote_pubkey"] == pubkeys[remote] and c.get("initiator") and c.get("active")
                for c in lnds[local].channels()
            ):
                return False
        return True

    wait_for("active channels", all_active, timeout=120)


def provision_maker(
    direction: str, xonly_by_direction: dict[str, str], evm: dict[str, Any] | None = None
) -> None:
    home = STATE / "makers" / direction
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    # Credentials are refreshed on every run; the config refers to them relatively.
    private_write(home / "core.cookie", CORE_COOKIE)
    private_write(home / "tls.cert", (STATE / "lnd/maker/tls.cert").read_bytes(), 0o644)
    private_write(home / "admin.macaroon", (STATE / "lnd/maker/admin.macaroon").read_bytes())

    custody = home / "custody.key"
    if not custody.exists():
        from pyrage import x25519

        identity = x25519.Identity.generate()
        private_write(custody, f"{identity}\n")
        private_write(home / "custody.recipient", f"{identity.to_public()}\n", 0o644)
    recipient = (home / "custody.recipient").read_text().strip()

    identity_file = home / "provider-identity.age"
    xonly_file = home / "provider.xonly"
    if not xonly_file.exists():
        # An identity without its recorded public key is an interrupted
        # attempt from before any config or store referenced it.
        identity_file.unlink(missing_ok=True)
        result = subprocess.run(
            [
                "rill-provider",
                "provision-identity",
                "--out",
                str(identity_file),
                "--recipient",
                recipient,
                "--native-crypto-library",
                CRYPTO,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        private_write(xonly_file, result.stdout.strip() + "\n", 0o644)
    xonly = xonly_file.read_text().strip()
    xonly_by_direction[direction] = xonly

    config_path = home / "provider.json"
    if evm is not None:
        from evm_dev import ANVIL_KEYS, ANVIL_RPC, FORWARD_MAKER, MAKER

        # One signer key per provider process: shared keys race for nonces.
        key = ANVIL_KEYS[FORWARD_MAKER] if direction == "erc20-to-ln" else ANVIL_KEYS[MAKER]
        private_write(home / "evm-signer.key", key + "\n")
    if not config_path.exists():
        maker_wallet = Core("maker")
        address = maker_wallet("getnewaddress", f"{direction}-destination", "bech32m")
        profile = f"{direction}/v1"
        config: dict[str, Any] = {
            "network": network_identity(),
            "provider_identity_xonly": xonly,
            "identity_file": "provider-identity.age",
            "store_path": "provider-store/live.sqlite",
            "custody_recipient": recipient,
            "custody_identity_file": "custody.key",
            "native_crypto_library": CRYPTO,
            "bitcoin_core": {"port": LOCAL_CORE_PORT, "cookie_file": "core.cookie"},
            "lnd": {
                "port": LOCAL_LND_PORT,
                "tls_certificate": "tls.cert",
                "macaroon": "admin.macaroon",
                "payment_macaroon": "admin.macaroon",
            },
            "provider_destination_script": maker_wallet("getaddressinfo", address)["scriptPubKey"],
            "authority": {
                "volume_label": f"dev-{direction}",
                "outside_restore_domain": True,
                "single_host": True,
            },
            "handshake": {
                "profile": profile,
                "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
                "capabilities": ["core/v1", "recovery/v1"],
            },
            "terms": {
                "profiles": [profile],
                "amount_bands": [[1000, 1_000_000]],
                "base_fee_sat": 50,
                "proportional_millionths": 1000,
                "slot": f"dev-{direction}",
            },
            "relay_urls": [RELAY_INTERNAL],
            # RS-006: cheap (about 256 hashes), but every client message is mined and checked.
            "transport_pow_bits": 8,
        }
        # Explicit test opt-in, only when creating a fresh config. Existing
        # stores/configs are never repriced or reprovisioned by this flag.
        if evm is None and os.environ.get("RILL_DEV_NETWORK_FEES") == "1":
            config["terms"]["network_fees"] = {
                "max_feerate_sat_kvb": 10000,
                "max_routing_fee_ppm": 1000,
            }
        if direction == "ln-to-btc":
            config["bitcoin_core"]["wallet"] = "maker"
            config["lnd"]["invoices_macaroon"] = "admin.macaroon"
        if evm is not None:
            # RS-010: no Taproot contract, so no destination script and no
            # cooperative claim feature; the HTLC signer is a dev Anvil key.
            del config["provider_destination_script"]
            config["lnd"]["invoices_macaroon"] = "admin.macaroon"
            config["evm"] = {
                "rpc_url": ANVIL_RPC,
                "chain_id": evm["chain_id"],
                "name": "anvil-dev",
                "htlc_contract": evm["htlc_contract"],
                "block_seconds": int(os.environ.get("RILL_DEV_ANVIL_BLOCK_SECONDS", "2")),
                "deployment_namespace": network_identity()["deployment_namespace"],
                "signer_key_file": "evm-signer.key",
                "tokens": [
                    {
                        "token_contract": evm["token_contract"],
                        "token_symbol": evm["token_symbol"],
                        "token_decimals": evm["token_decimals"],
                        "rate_token_base_per_btc": evm["rate_token_base_per_btc"],
                    }
                ],
                "funding_confirmations": 1,
                "settlement_confirmations": 1,
                # 2 s blocks. RS-010 requires the client's lock to outlast the outgoing
                # Lightning budget (144 BTC blocks at 600 s) plus learn_and_claim_seconds,
                # so the forward lock is refundable after ~25 h; ours after ~1 h.
                "forward_timelock_delay_blocks": 45_000,
                "reverse_timelock_delay_blocks": 1800,
                "learn_and_claim_seconds": 600,
                "refund_and_ln_resolution_seconds": 600,
            }
        private_write(config_path, json.dumps(config, indent=1) + "\n")

    store = home / "provider-store"
    if not (store / "live.sqlite").exists():
        if store.exists():
            shutil.rmtree(store)  # interrupted provisioning, never served
        store.mkdir(mode=0o700)
        log(f"provisioning {direction} maker store")
        subprocess.run(
            ["rill-provider", "provision-store", "--config", str(config_path)], check=True
        )


def provision_user() -> None:
    home = STATE / "user"
    (home / "swaps").mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    private_write(home / "core.cookie", CORE_COOKIE)
    private_write(home / "tls.cert", (STATE / "lnd/user/tls.cert").read_bytes(), 0o644)
    private_write(home / "admin.macaroon", (STATE / "lnd/user/admin.macaroon").read_bytes())
    private_write(home / "network.json", json.dumps(network_identity()) + "\n", 0o644)
    if not (home / "age.key").exists():
        from pyrage import x25519

        identity = x25519.Identity.generate()
        private_write(home / "age.key", f"{identity}\n")
        private_write(home / "age.recipient", f"{identity.to_public()}\n", 0o644)


def provision_browser_node(directory: Path = Path("/browser-node")) -> None:
    """Explicit bootstrap only: a dedicated credential, never an admin export."""
    from user_node_api import METHODS

    names = {"configuration.json", "browser.macaroon", "tls.cert"}
    present = {path.name for path in directory.iterdir()}
    if present:
        if present != names:
            raise SystemExit("Partial browser node credentials preserved; browser access disabled")
        config = json.loads((directory / "configuration.json").read_text())
        if (
            config.get("permissions") != sorted(METHODS)
            or config.get("network_identity") != network_identity()
        ):
            raise SystemExit(
                "Unsupported browser node credentials preserved; browser access disabled"
            )
        # Existing files are never silently regenerated, repaired, or escalated.
        return
    lnd = Lnd("user")
    info = lnd.info()
    if info.get("chains") != [{"chain": "bitcoin", "network": "regtest"}]:
        raise SystemExit("Browser access requires the disposable regtest node")
    config = {
        "node_identity": info["identity_pubkey"],
        "network_identity": network_identity(),
        "permissions": sorted(METHODS),
    }
    # Record intent first. An interruption leaves partial state blocked, not regenerated.
    private_write(directory / "configuration.json", json.dumps(config) + "\n", 0o644)
    baked = lnd.post(
        "/v1/macaroon",
        {"permissions": [{"entity": "uri", "action": method} for method in sorted(METHODS)]},
    )
    private_write(directory / "browser.macaroon", bytes.fromhex(baked["macaroon"]))
    private_write(directory / "tls.cert", (STATE / "lnd/user/tls.cert").read_bytes(), 0o644)


def provision_merchant(lnd: Lnd) -> None:
    """Files for `bun src/cli.ts provision|serve` (rill-payments merchant CLI).

    Keys, token and config are created once; the merchant container provisions
    its ledger itself on first start. The CLI requires absolute paths and
    private single-link regular files.
    """
    home = MERCHANT_DIR
    (home / "ledger").mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    (home / "ledger").chmod(0o700)
    private_write(home / "tls.cert", (STATE / "lnd/merchant/tls.cert").read_bytes(), 0o644)
    for name in ("issuance.key", "status.key", "event.key"):
        if not (home / name).exists():
            private_write(home / name, secrets.token_bytes(32))
    if not (home / "admin.token").exists():
        private_write(home / "admin.token", secrets.token_urlsafe(48))
    if not (home / "invoice.macaroon").exists():
        baked = lnd.post(
            "/v1/macaroon",
            {
                "permissions": [
                    {"entity": "info", "action": "read"},
                    {"entity": "invoices", "action": "read"},
                    {"entity": "invoices", "action": "write"},
                ]
            },
        )
        private_write(home / "invoice.macaroon", bytes.fromhex(baked["macaroon"]))
    if not (home / "config.json").exists():
        config = {
            "network": "regtest",
            "origin": MERCHANT_ORIGIN,
            "receiver": lnd.pubkey(),
            "endpoint": "https://127.0.0.1:8080/",
            "ledgerPath": str(home / "ledger/merchant.sqlite"),
            "certificatePath": str(home / "tls.cert"),
            "macaroonPath": str(home / "invoice.macaroon"),
            "issuanceKeyPath": str(home / "issuance.key"),
            "statusKeyPath": str(home / "status.key"),
            "eventKeyPath": str(home / "event.key"),
            "adminTokenPath": str(home / "admin.token"),
        }
        private_write(home / "config.json", json.dumps(config, indent=1) + "\n")


def write_info(
    lnds: dict[str, Lnd], makers: dict[str, str], monero: dict[str, str], evm: dict[str, Any]
) -> dict[str, Any]:
    info = {
        "makers": makers,
        "evm": evm,
        "relay": {"containers": RELAY_INTERNAL, "host": RELAY_HOST},
        "lnd_pubkeys": {node: lnd.pubkey() for node, lnd in lnds.items()},
        "user_age_recipient": (STATE / "user/age.recipient").read_text().strip(),
        "merchant": {"origin": MERCHANT_ORIGIN, "lnd_pubkey": lnds["merchant"].pubkey()},
        "monero_addresses": monero,
        "network": network_identity(),
    }
    private_write(STATE / "info.json", json.dumps(info, indent=1) + "\n", 0o644)
    # Public browser pins come from the operator-owned deployment, never relay metadata.
    # Re-create this configuration on upgrades without deploying or minting again.
    asset = {
        "family": "evm",
        "chain_id": evm["chain_id"],
        "name": "anvil-dev",
        "htlc_contract": evm["htlc_contract"],
        "htlc_version": 6,
        "token_contract": evm["token_contract"],
        "token_symbol": evm["token_symbol"],
        "token_decimals": evm["token_decimals"],
        "block_seconds": int(os.environ.get("RILL_DEV_ANVIL_BLOCK_SECONDS", "2")),
        "deployment_namespace": info["network"]["deployment_namespace"],
    }
    private_write(STATE / "evm/browser-assets.json", json.dumps({"USDC": asset}) + "\n", 0o644)
    return info


def cmd_bootstrap(_: argparse.Namespace) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    wait_for("bitcoind", lambda: Core()("getblockcount") is not None)
    for node in LND_NODES:
        copy_lnd_credentials(node)
    lnds = {node: Lnd(node) for node in LND_NODES}
    wait_for("LND servers", lambda: all(lnd.info() for lnd in lnds.values()))
    ensure_chain_and_funds(lnds)
    ensure_channels(lnds)
    makers: dict[str, str] = {}
    for direction in DIRECTIONS:
        provision_maker(direction, makers)
    from evm_dev import ensure_evm

    evm = ensure_evm(STATE, log)
    for direction in EVM_DIRECTIONS:
        provision_maker(direction, makers, evm)
    provision_user()
    provision_browser_node()
    provision_merchant(lnds["merchant"])
    monero = ensure_monero()
    write_info(lnds, makers, monero, evm)
    log(f"bootstrap complete at height {Core()('getblockcount')}")


# --- miner -------------------------------------------------------------------


def monero_mine_loop(interval: float, paused: Path) -> None:
    daemon = MoneroDaemon()
    address = load_info()["monero_addresses"]["buyer"]
    while True:
        time.sleep(interval)
        if paused.exists():
            continue
        try:
            daemon.mine(1, address)
        except (httpx.HTTPError, RpcError) as error:
            log(f"Monero mining failed: {error}")


def cmd_mine_loop(_: argparse.Namespace) -> None:
    interval = float(os.environ.get("RILL_DEV_BLOCK_SECONDS", "10"))
    monero_interval = float(os.environ.get("RILL_DEV_MONERO_BLOCK_SECONDS", "2"))
    paused = STATE / "miner.paused"
    log(f"auto-mining one block every {interval:g}s (0 disables; pause with `devctl miner pause`)")
    if monero_interval > 0:
        log(f"auto-mining one Monero block every {monero_interval:g}s to the buyer")
        threading.Thread(
            target=monero_mine_loop, args=(monero_interval, paused), daemon=True
        ).start()
    while True:
        time.sleep(interval if interval > 0 else 60)
        if interval <= 0 or paused.exists():
            continue
        try:
            mine(1)
        except (httpx.HTTPError, RpcError) as error:
            log(f"mining failed: {error}")


def cmd_mine(args: argparse.Namespace) -> None:
    print(f"height {mine(args.blocks)}")


def cmd_miner(args: argparse.Namespace) -> None:
    flag = STATE / "miner.paused"
    if args.action == "pause":
        flag.touch()
    elif args.action == "resume":
        flag.unlink(missing_ok=True)
    print("auto-miner " + ("paused" if flag.exists() else "running"))


# --- user commands -----------------------------------------------------------


def load_info() -> dict[str, Any]:
    path = STATE / "info.json"
    if not path.exists():
        raise SystemExit("stack not bootstrapped yet; run `devctl up` and wait for bootstrap")
    return json.loads(path.read_text())


def lnd_summary(node: str) -> dict[str, int]:
    lnd = Lnd(node)
    channels = lnd.channels()
    return {
        "onchain_sat": lnd.onchain_sat(),
        "channel_local_sat": sum(int(c.get("local_balance", 0)) for c in channels),
        "channel_remote_sat": sum(int(c.get("remote_balance", 0)) for c in channels),
    }


def balances() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for wallet in ("user", "maker"):
        mine_balances = Core(wallet)("getbalances")["mine"]
        result[f"core:{wallet}"] = {
            "trusted_btc": mine_balances["trusted"],
            "pending_btc": mine_balances["untrusted_pending"],
        }
    for node in LND_NODES:
        result[f"lnd:{node}"] = lnd_summary(node)
    for name in MONERO_WALLETS:
        result[f"monero:{name}"] = MoneroWallet(name).balance()
    return result


def cmd_info(args: argparse.Namespace) -> None:
    info = load_info()
    info["height"] = Core()("getblockcount")
    info["auto_miner"] = "paused" if (STATE / "miner.paused").exists() else "running"
    info["balances"] = balances()
    if args.json:
        print(json.dumps(info, indent=1))
        return
    print(f"height          {info['height']} (auto-miner {info['auto_miner']})")
    print(f"monero height   {MoneroDaemon().height()}")
    print(f"relay (host)    {info['relay']['host']}")
    print(f"relay (stack)   {info['relay']['containers']}")
    for direction, xonly in info["makers"].items():
        print(f"maker {direction:<11} {xonly}")
    print(f"user age key    {info['user_age_recipient']}")
    evm = info.get("evm", {})
    if evm:
        print(f"evm htlc        {evm['htlc_contract']} (chain {evm['chain_id']})")
        print(f"evm token       {evm['token_contract']} {evm['token_symbol']}")
        print(f"evm user        {evm['user_address']}")
    for name, value in info["balances"].items():
        print(f"{name:<15} {json.dumps(value)}")


def cmd_balances(_: argparse.Namespace) -> None:
    print(json.dumps(balances(), indent=1))


def cmd_invoice(args: argparse.Namespace) -> None:
    print(Lnd(args.node).add_invoice(args.sat, args.memo))


def cmd_pay(args: argparse.Namespace) -> None:
    result = Lnd(args.node).pay(args.bolt11)
    if result.get("status") != "SUCCEEDED":
        reason = result.get("failure_reason", "no final status")
        raise SystemExit(f"payment failed: {result.get('status')} {reason}")
    print(f"paid, preimage {result['payment_preimage']}, fee {result.get('fee_sat', '0')} sat")


def cmd_address(args: argparse.Namespace) -> None:
    print(Core(args.wallet)("getnewaddress", "", "bech32m"))


def cmd_sign_psbt(args: argparse.Namespace) -> None:
    signed = Core(args.wallet)("walletprocesspsbt", args.psbt, True, "ALL", True, True)
    if not signed["complete"]:
        raise SystemExit("wallet could not fully sign this PSBT")
    print(signed["psbt"])
    if args.hex:
        print(signed["hex"], file=sys.stderr)


def cmd_fund_psbt(args: argparse.Namespace) -> None:
    """Pay `amount` BTC to `address` from a Core wallet as a finalized PSBT."""
    wallet = Core(args.wallet)
    created = wallet(
        "walletcreatefundedpsbt",
        [],
        [{args.address: args.amount}],
        0,
        {"fee_rate": 2, "change_type": "bech32"},
    )
    signed = wallet("walletprocesspsbt", created["psbt"], True)
    if not signed["complete"]:
        raise SystemExit("wallet could not fully sign the funding PSBT")
    print(signed["psbt"])


def btc_amount(value: str) -> str:
    """Keep fixed-point BTC exact through argparse and the Core RPC boundary."""
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?", value)
        or not 0 < Decimal(value) <= 21_000_000
    ):
        raise argparse.ArgumentTypeError(
            "BTC amount must be positive with at most 8 decimal places"
        )
    return value


def cmd_send_btc(args: argparse.Namespace) -> None:
    """Send the exact BTC amount now, with fees paid separately by the user wallet."""
    amount = btc_amount(args.amount)
    info = Core()("getblockchaininfo")
    if not isinstance(info, dict) or info.get("chain") != "regtest":
        raise SystemExit("send-btc requires the disposable regtest chain")
    print(Core("user")("sendtoaddress", args.address, amount, "", "", False))


def cmd_web_inputs(args: argparse.Namespace) -> None:
    """Print every value the swap.html BTC->LN form asks for."""
    info = load_info()
    print("Network                 regtest")
    print(f"Relay                   {info['relay']['host']}")
    print(f"Provider identity       {info['makers']['btc-to-ln']}")
    print(f"Lightning invoice       {Lnd('user').add_invoice(args.sat, 'rill web swap')}")
    print(f"Refund address          {Core('user')('getnewaddress', '', 'bech32m')}")
    print(f"Current block height    {Core()('getblockcount')}")
    print(f"Recovery age recipient  {info['user_age_recipient']}")


def cmd_broadcast(args: argparse.Namespace) -> None:
    print(Core()("sendrawtransaction", args.tx))


def cmd_swap(args: argparse.Namespace) -> None:
    info = load_info()
    user = STATE / "user"
    swaps = user / "swaps"
    swaps.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(
        tempfile.mkdtemp(prefix=f"{time.strftime('%Y%m%dT%H%M%S')}-{args.direction}-", dir=swaps)
    )
    command = [
        "rill",
        "swap",
        args.direction,
        "--network",
        str(user / "network.json"),
        "--crypto-library",
        CRYPTO,
        "--relay",
        RELAY_INTERNAL,
        "--provider",
        info["makers"][args.direction],
        "--max-success-fee-sat",
        str(args.max_fee),
        "--core-port",
        str(LOCAL_CORE_PORT),
        "--core-cookie",
        str(user / "core.cookie"),
        "--wallet",
        "user",
        "--lnd-port",
        str(LOCAL_LND_PORT),
        "--lnd-tls-cert",
        str(user / "tls.cert"),
        "--lnd-macaroon",
        str(user / "admin.macaroon"),
        "--recipient",
        info["user_age_recipient"],
        "--identity",
        str(user / "age.key"),
        "--recovery-output",
        str(work / "recovery.age"),
        "--settle-timeout",
        str(args.settle_timeout),
    ]
    target = str(args.target)
    if args.direction == "btc-to-ln":
        if target.startswith("lnbcrt"):
            bolt11 = target  # e.g. a shop invoice
        else:
            bolt11 = Lnd("user").add_invoice(int(target), "rill dev swap")
            log(f"user invoice for {target} sat: {bolt11}")
        command += ["--invoice", bolt11]
    elif target.startswith("lnbcrt"):
        raise SystemExit("ln-to-btc takes a payout amount in sat, not an invoice")
    else:
        command += ["--payout-sat", str(int(target))]
    command += args.extra
    log(f"recovery files in {work}")
    log("running: " + " ".join(command))
    raise SystemExit(subprocess.run(command, check=False).returncode)


def shop(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    response = httpx.request(method, SHOP_URL + path, json=body, timeout=30)
    response.raise_for_status()
    return response.json()


def new_shop_order(rail: str) -> dict[str, Any]:
    """Order stickers once the merchant's LND has caught up with the chain tip.

    The merchant refuses Lightning intents while its LND trails a new block,
    which is likely right after a swap's claim has just confirmed.
    """
    wait_lnd_synced([Lnd("merchant")])
    return shop("POST", "/api/orders", {"productId": "stickers", "rail": rail})


def cmd_shop_smoke(_: argparse.Namespace) -> None:
    """Buy from the demo shop over Lightning and via a btc-to-ln swap."""
    for rail in ("lightning", "btc-swap"):
        order = new_shop_order(rail)
        log(f"shop order {order['id']} ({rail}, {order['amountSat']} sat)")
        if rail == "lightning":
            result = Lnd("user").pay(order["invoice"])
            if result.get("status") != "SUCCEEDED":
                raise SystemExit(f"shop payment failed: {result}")
        else:
            code = subprocess.run(
                [sys.executable, __file__, "swap", "btc-to-ln", order["invoice"]], check=False
            ).returncode
            if code:
                raise SystemExit(f"swap for shop order failed with exit {code}")
        accepted = wait_for(
            f"signed acceptance for order {order['id']}",
            lambda order=order: shop("GET", f"/api/orders/{order['id']}")["acceptance"],
            timeout=60,
            interval=2,
        )
        log(f"order {order['id']} paid, acceptance {accepted['eventId']} verified")


def cmd_pay_xmr(args: argparse.Namespace) -> None:
    """Pay a demo shop Monero order from the buyer wallet, optionally in parts."""
    order = shop("GET", f"/api/orders/{args.order}")
    if not order.get("monero"):
        raise SystemExit(f"order {args.order} is not a Monero order")
    terms = order["monero"]["terms"]
    total = int(terms["amountAtomic"])
    parts = [total // args.parts] * (args.parts - 1)
    parts.append(total - sum(parts))
    buyer = MoneroWallet("buyer")
    buyer("refresh")
    for amount in parts:
        tx = buyer(
            "transfer",
            destinations=[{"address": terms["address"], "amount": amount}],
            account_index=0,
            priority=0,
        )
        log(f"sent {amount / PICONERO:.12g} XMR to order {args.order}: tx {tx['tx_hash']}")


def cmd_xmr_smoke(_: argparse.Namespace) -> None:
    """Buy from the demo shop with Monero: one payment, then one split in two transactions."""
    for parts in (1, 2):
        order = new_shop_order("monero")
        log(f"shop order {order['id']} (monero, {order['amountLabel']}, {parts} tx)")
        cmd_pay_xmr(argparse.Namespace(order=order["id"], parts=parts))
        accepted = wait_for(
            f"signed acceptance for order {order['id']}",
            lambda order=order: shop("GET", f"/api/orders/{order['id']}")["acceptance"],
            timeout=180,
            interval=2,
        )
        log(f"order {order['id']} paid, acceptance {accepted['eventId']} verified")
        log(f"evidence: {accepted['detail']}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="devtool", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap", help="idempotently prepare chain, channels and makers")
    sub.add_parser("mine-loop", help="auto-miner service loop")
    p = sub.add_parser("mine", help="mine blocks now")
    p.add_argument("blocks", type=int, nargs="?", default=1)
    p = sub.add_parser("miner", help="pause/resume the auto-miner")
    p.add_argument("action", choices=["pause", "resume", "status"])
    p = sub.add_parser("info", help="maker keys, relay URLs, height and balances")
    p.add_argument("--json", action="store_true")
    sub.add_parser("balances", help="Core wallets, LND nodes and Monero wallets")
    p = sub.add_parser("invoice", help="create a BOLT11 invoice")
    p.add_argument("sat", type=int)
    p.add_argument("--node", choices=LND_NODES, default="user")
    p.add_argument("--memo", default="rill dev")
    p = sub.add_parser("pay", help="pay a BOLT11 invoice")
    p.add_argument("bolt11")
    p.add_argument("--node", choices=LND_NODES, default="user")
    p = sub.add_parser("address", help="new bech32m address in a Core wallet")
    p.add_argument("--wallet", choices=["user", "maker", "miner"], default="user")
    p = sub.add_parser("sign-psbt", help="sign and finalize a PSBT with a Core wallet")
    p.add_argument("psbt")
    p.add_argument("--wallet", default="user")
    p.add_argument("--hex", action="store_true", help="also print raw tx hex to stderr")
    p = sub.add_parser("fund-psbt", help="finalized PSBT paying ADDRESS the exact BTC amount")
    p.add_argument("address")
    p.add_argument("amount", help="BTC amount exactly as shown, e.g. 0.00050100")
    p.add_argument("--wallet", default="user")
    p = sub.add_parser(
        "send-btc", help="send ADDRESS the exact BTC amount from the regtest user wallet"
    )
    p.add_argument("address")
    p.add_argument("amount", type=btc_amount, help="BTC amount, e.g. 0.00100150 (fees are extra)")
    p = sub.add_parser("web-inputs", help="values for the swap.html form")
    p.add_argument("sat", type=int, nargs="?", default=50_000)
    p = sub.add_parser("broadcast", help="broadcast a raw transaction hex")
    p.add_argument("tx")
    sub.add_parser("shop-smoke", help="buy from the demo shop (Lightning and on-chain swap)")
    p = sub.add_parser("pay-xmr", help="pay a demo shop Monero order from the buyer wallet")
    p.add_argument("order")
    p.add_argument("--parts", type=int, default=1, help="split into this many transactions")
    sub.add_parser("xmr-smoke", help="buy from the demo shop with Monero")
    p = sub.add_parser("swap", help="run a user swap against the local maker")
    p.add_argument("direction", choices=DIRECTIONS)
    p.add_argument(
        "target", nargs="?", default="50000", help="amount in sat, or (btc-to-ln) a BOLT11 to pay"
    )
    p.add_argument("--max-fee", type=int, default=2000, help="max success fee in sat")
    p.add_argument("--settle-timeout", type=int, default=600)
    p.add_argument("extra", nargs=argparse.REMAINDER, help="extra `rill swap` flags")
    args = parser.parse_args()
    handlers = {
        "bootstrap": cmd_bootstrap,
        "mine-loop": cmd_mine_loop,
        "mine": cmd_mine,
        "miner": cmd_miner,
        "info": cmd_info,
        "balances": cmd_balances,
        "invoice": cmd_invoice,
        "pay": cmd_pay,
        "address": cmd_address,
        "sign-psbt": cmd_sign_psbt,
        "fund-psbt": cmd_fund_psbt,
        "send-btc": cmd_send_btc,
        "web-inputs": cmd_web_inputs,
        "broadcast": cmd_broadcast,
        "swap": cmd_swap,
        "shop-smoke": cmd_shop_smoke,
        "pay-xmr": cmd_pay_xmr,
        "xmr-smoke": cmd_xmr_smoke,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
