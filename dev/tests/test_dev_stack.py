"""Static checks for the regtest dev stack (dev/compose.yaml, dev/devtool.py)."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "dev/compose.yaml").read_text()


def test_ci_overlay_only_disables_application_watchers():
    overlay = (ROOT / "dev/compose.ci.yaml").read_text()
    assert set(re.findall(r"^  ([a-z-]+):", overlay, re.M)) == {"shop", "web"}
    assert re.findall(r"^    ([a-z_]+):", overlay, re.M) == ["command", "command"]
    assert "command: [bun, server.ts]" in overlay
    assert "vite build &&" in overlay
    assert "vite preview --host 0.0.0.0 --port 5173 --strictPort" in overlay
    assert "--watch" not in overlay
    # The normal development stack retains its existing hot-reload behavior.
    assert "command: [bun, --watch, server.ts]" in COMPOSE


def test_relay_resilience_overlay_keeps_the_base_primary_port_default() -> None:
    overlay = (ROOT / "dev/compose.relay-resilience.yaml").read_text()
    base = re.findall(r"\$\{RILL_DEV_RELAY_PORT:-(\d+)\}", COMPOSE)
    assert base
    assert set(re.findall(r"\$\{RILL_DEV_RELAY_PORT:-(\d+)\}", overlay)) == set(base)
    assert "RILL_DEV_PROVIDER_RELAYS:" in overlay
    assert "127.0.0.1:${RILL_DEV_RELAY_ALT_PORT:-17778}:8080" in overlay


def test_web_mounts_build_helpers_read_only() -> None:
    assert "../rill-web/scripts:/src/rill-web/scripts:ro" in compose_service("web")
    assert (ROOT / "rill-web/scripts/build-commit.ts").is_file()


def load_devtool():
    pytest.importorskip("httpx")
    spec = importlib.util.spec_from_file_location("devtool", ROOT / "dev/devtool.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rpcauth_entries() -> dict[str, tuple[str, str]]:
    entries = {}
    for user, salt, digest in re.findall(r"-rpcauth=([^:]+):([0-9a-f]+)\$\$([0-9a-f]+)", COMPOSE):
        entries[user] = (salt, digest)
    return entries


def matches(user: str, password: str) -> bool:
    salt, digest = rpcauth_entries()[user]
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest() == digest


def test_rpcauth_matches_devtool_credentials():
    devtool = load_devtool()
    user, password = devtool.CORE_AUTH
    assert matches(user, password)
    assert f"--bitcoind.rpcuser={user}" in COMPOSE
    assert f"--bitcoind.rpcpass={password}" in COMPOSE


def test_static_cookie_matches_rpcauth():
    devtool = load_devtool()
    user, password = devtool.CORE_COOKIE.strip().split(":", 1)
    # Rill's cookie reader only accepts the `__cookie__` username.
    assert user == "__cookie__"
    assert matches(user, password)


def test_chain_reader_is_whitelisted_loopback_only_and_stateless():
    assert matches("rill-chain", "rill-dev-chain-regtest")
    assert (
        "-rpcwhitelist=rill-chain:getblockchaininfo,getblockhash,getrawtransaction,getblockheader,gettxout,getdescriptoractivity"
        in COMPOSE
    )
    assert "-rpcwhitelistdefault=0" in COMPOSE
    service = compose_service("chain")
    assert "127.0.0.1:${RILL_DEV_CHAIN_PORT:-8091}:8091" in service
    assert "./chain_api.py:/src/dev/chain_api.py:ro" in service
    assert "state:/state" not in service and "<<: *rill" not in service
    assert (
        "VITE_RILLSWAP_MEMPOOL_API: http://127.0.0.1:${RILL_DEV_CHAIN_PORT:-8091}/api"
        in compose_service("web")
    )
    assert (
        "VITE_RILLSWAP_NODE_API: http://127.0.0.1:${RILL_DEV_NODE_PORT:-8093}"
        in compose_service("web")
    )


def test_has_channel_counts_open_and_pending_local_initiator():
    devtool = load_devtool()

    class FakeLnd:
        def __init__(self, channels, pending):
            self._channels, self._pending = channels, pending

        def channels(self):
            return self._channels

        def pending_open(self):
            return self._pending

    remote = "02" + "ab" * 32
    assert devtool.has_channel(FakeLnd([{"remote_pubkey": remote, "initiator": True}], []), remote)
    assert not devtool.has_channel(
        FakeLnd([{"remote_pubkey": remote, "initiator": False}], []), remote
    )
    pending = [{"channel": {"remote_node_pub": remote, "initiator": "INITIATOR_LOCAL"}}]
    assert devtool.has_channel(FakeLnd([], pending), remote)
    remote_pending = [{"channel": {"remote_node_pub": remote, "initiator": "INITIATOR_REMOTE"}}]
    assert not devtool.has_channel(FakeLnd([], remote_pending), remote)


def test_shop_orders_wait_for_the_merchant_lnd_to_reach_the_tip(monkeypatch) -> None:
    devtool = load_devtool()
    calls = []
    monkeypatch.setattr(devtool, "Lnd", lambda node: f"lnd-{node}")
    monkeypatch.setattr(devtool, "wait_lnd_synced", lambda nodes: calls.append(("sync", nodes)))

    def shop(method, path, body):
        calls.append((method, path, body))
        return {"id": "o"}

    monkeypatch.setattr(devtool, "shop", shop)
    assert devtool.new_shop_order("lightning") == {"id": "o"}
    assert calls == [
        ("sync", ["lnd-merchant"]),  # a just-confirmed claim leaves its LND a block behind
        ("POST", "/api/orders", {"productId": "stickers", "rail": "lightning"}),
    ]


def compose_service(name: str) -> str:
    match = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", COMPOSE, re.M | re.S)
    assert match, name
    return match.group(1)


def test_shared_image_has_one_builder_reachable_from_every_consumer():
    service_config = COMPOSE.split("\nservices:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    services = {
        name: compose_service(name)
        for name in re.findall(r"^  ([a-z][a-z0-9-]*):$", service_config, re.M)
    }
    consumers = {
        name
        for name, body in services.items()
        if "<<: *rill" in body or "image: rillswap-dev:local" in body
    }
    builders = {name for name in consumers if re.search(r"^    build:", services[name], re.M)}
    assert builders == {"chain"}
    assert COMPOSE.count("dockerfile: dev/Dockerfile") == 1

    for consumer in consumers:
        pending = [consumer]
        reached = set()
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            reached.add(name)
            dependencies = re.search(r"^    depends_on:\n((?: {6,}.+\n)*)", services[name], re.M)
            if dependencies:
                pending.extend(re.findall(r"^      ([a-z][a-z0-9-]*):$", dependencies[1], re.M))
        assert "chain" in reached, f"{consumer} cannot build the shared image on a cold start"


def test_monero_chain_persists_and_wallet_rpc_stays_private():
    monerod = compose_service("monerod")
    # Without --keep-fakechain monerod deletes the regtest chain at every start.
    for flag in ("--regtest", "--keep-fakechain", "--offline", "--fixed-difficulty=1"):
        assert flag in monerod
    wallet = COMPOSE.split("x-monero-wallet: &monero-wallet", 1)[1].split("\nx-", 1)[0]
    assert "--disable-rpc-login" in wallet
    for name in ("monerod", "monero-wallet-merchant", "monero-wallet-buyer"):
        assert "ports:" not in compose_service(name)
        assert "ports:" not in wallet


def test_monero_wallet_reopens_after_wallet_rpc_restart(monkeypatch):
    devtool = load_devtool()
    calls = []
    opened = {"wallet": False}

    def raw(self, method, **params):
        calls.append(method)
        if method == "open_wallet":
            opened["wallet"] = True
            return {}
        if not opened["wallet"]:
            raise devtool.RpcError(-13, "No wallet file")
        return {"height": 5}

    monkeypatch.setattr(devtool.MoneroWallet, "raw", raw)
    assert devtool.MoneroWallet("merchant")("get_height") == {"height": 5}
    assert calls == ["get_height", "open_wallet", "get_height"]
    monkeypatch.setattr(
        devtool.MoneroWallet,
        "raw",
        lambda self, method, **params: (_ for _ in ()).throw(devtool.RpcError(-1, "other")),
    )
    with pytest.raises(devtool.RpcError):
        devtool.MoneroWallet("merchant")("get_height")


def test_monero_wallet_created_only_in_an_empty_volume(tmp_path, monkeypatch):
    devtool = load_devtool()
    calls = []
    monkeypatch.setattr(devtool, "MONERO_WALLET_DIRS", tmp_path / "wallets")
    monkeypatch.setattr(devtool, "STATE", tmp_path / "state")
    monkeypatch.setattr(
        devtool.MoneroWallet, "raw", lambda self, method, **params: calls.append(method) or {}
    )
    with pytest.raises(SystemExit, match="not mounted"):
        devtool.ensure_monero_wallet("merchant")
    (tmp_path / "wallets/merchant").mkdir(parents=True)
    devtool.ensure_monero_wallet("merchant")
    assert calls == ["create_wallet"]
    (tmp_path / "wallets/merchant/merchant.keys").write_text("")
    devtool.ensure_monero_wallet("merchant")
    assert calls[-1] == "open_wallet"
    (tmp_path / "wallets/merchant/merchant.keys").unlink()
    (tmp_path / "state/shop/monero").mkdir(parents=True)
    (tmp_path / "state/shop/monero/ledger.sqlite-wal").write_text("")
    with pytest.raises(SystemExit, match="shop's Monero state"):
        devtool.ensure_monero_wallet("merchant")


def test_evm_makers_run_after_bootstrap_deploys_on_a_healthy_anvil():
    bootstrap = compose_service("bootstrap")
    assert "anvil:\n        condition: service_healthy" in bootstrap
    for direction in ("erc20-to-ln", "ln-to-erc20"):
        maker = compose_service(f"maker-{direction}")
        assert f"/state/makers/{direction}/provider.json" in maker
        assert "bootstrap:\n        condition: service_completed_successfully" in maker
    devtool = (ROOT / "dev/devtool.py").read_text()
    assert 'EVM_DIRECTIONS = ("erc20-to-ln", "ln-to-erc20")' in devtool
    evm = (ROOT / "dev/evm_dev.py").read_text()
    # Distinct dev roles: the maker's HTLC signer is not the deployer, user, or gas sponsor.
    assert "DEPLOYER, USER, _SHOP, MAKER, SPONSOR = range(5)" in evm
    assert "ANVIL_KEYS[MAKER]" in devtool
    sponsor = (ROOT / "dev/gas_sponsor.py").read_text()
    assert "ANVIL_KEYS[SPONSOR]" in sponsor
    for artifact in (
        "rill-contracts/artifacts/erc20-swap-v6.json",
        "rill-payments/examples/demo-shop/dev-stablecoin.json",
    ):
        assert artifact in evm
        assert (ROOT / artifact).exists()
    for artifact in ("entry-point-v0.7.json", "execution-install-delegate.json", "sma7702.json"):
        assert f'"{artifact}"' in evm
        assert (ROOT / "rill-contracts/artifacts" / artifact).exists()


def test_gas_sponsor_serves_the_web_client_only_from_the_dev_stack():
    service = compose_service("gas-sponsor")
    assert "command: [python, /src/dev/gas_sponsor.py]" in service
    assert "bootstrap:\n        condition: service_completed_successfully" in service
    assert "127.0.0.1:${RILL_DEV_SPONSOR_PORT:-8094}:8094" in service
    web = compose_service("web")
    assert "VITE_RILLSWAP_EVM_SPONSOR: http://127.0.0.1:${RILL_DEV_SPONSOR_PORT:-8094}" in web
    assert "VITE_RILLSWAP_EVM_ENTRY_POINT" in web and "VITE_RILLSWAP_EVM_7702_DELEGATE" in web


def test_browser_asset_pins_come_from_bootstrap_not_provider_discovery():
    web = compose_service("web")
    assert "state:/state:ro" in web
    assert "bootstrap:\n        condition: service_completed_successfully" in web
    assert 'VITE_RILLSWAP_EVM_ASSETS="$$(cat /state/evm/browser-assets.json)"' in web
    overlay = (ROOT / "dev/compose.ci.yaml").read_text()
    assert 'VITE_RILLSWAP_EVM_ASSETS="$$(cat /state/evm/browser-assets.json)"' in overlay
