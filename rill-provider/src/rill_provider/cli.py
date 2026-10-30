"""``rill-provider`` operator entrypoint: provision identity/store, then serve.

Provisioning is explicit and never overwrites. ``serve`` takes lifetime
ownership of the store and runs the handshake service until SIGINT/SIGTERM.
Errors are printed as one redacted line; exit status 2 means refused.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import json
import logging
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from rill_core.errors import ValidationError
from rill_core.networks import require_supported_network

from rill_provider.core_tx_bytes import CoreTransactionReader
from rill_provider.diagnostics import (
    CHATTY_LIBRARY_LOGGERS as _LIBRARY_LOGGERS,
)
from rill_provider.diagnostics import (
    configure_logging,
    diagnostic,
    diagnostic_context,
)
from rill_provider.dynamic_pricing import BTC_RESERVE, LiquiditySample, LiquiditySampler
from rill_provider.evm_htlc import EvmBackendError, EvmHtlcClient
from rill_provider.evm_quote_policy import EVM_PROFILES, EvmQuotePrices
from rill_provider.evm_settlement import EvmSettlementEngine
from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import LiveSessionStore, LiveSessionStoreError
from rill_provider.lnd_hold_invoice import LndHoldInvoices
from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
from rill_provider.lnd_payment_observation import LndObservationError
from rill_provider.lnd_payment_send import LndPaymentSender
from rill_provider.notification_balances import (
    balance_readers,
    channel_amount_msat,
    evm_token_balances,
    lnd_channel_balance,
)
from rill_provider.notifications import Notifier, notification_sender
from rill_provider.operator_config import (
    OperatorConfig,
    OperatorConfigError,
    load_config,
    read_custody_identity,
    read_evm_signer_key,
)
from rill_provider.payment_reconciliation import reconcile_payment
from rill_provider.price_feeds import (
    PriceFeed,
    PriceUnavailableError,
    Side,
    gas_wei_as_token_base,
    rate_token_base_per_btc,
)
from rill_provider.provider_identity import ProviderIdentity, ProviderIdentityError
from rill_provider.quote_policy import ClaimFeeRate, normal_service_fee
from rill_provider.relay_client import (
    RelayConnection,
    RelayError,
    reachable_relays,
    require_relay_route,
)
from rill_provider.settlement_engine import EngineSettings, SettlementEngine

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rill_core.wire.messages import InvoiceBinding
    from rill_crypto import Context

REFUSED = 2
# Preserve the entrypoint's existing logger-policy surface.
CHATTY_LIBRARY_LOGGERS = _LIBRARY_LOGGERS
# Client libraries that log every request at INFO (httpx: each Core RPC call).
# They only speak up at WARNING unless --log-level DEBUG asks for everything.
# Apprise runs in its own process, which logs nothing (notification_worker).


def _context(library: Path) -> Context:
    from rill_crypto import Context  # noqa: PLC0415 - native library loads only when needed

    return Context(library_path=str(library))


def _provision_identity(args: argparse.Namespace) -> int:
    with _context(args.native_crypto_library) as crypto:
        xonly = ProviderIdentity.provision(args.out, recipient=args.recipient, crypto=crypto)
    print(xonly)  # noqa: T201 - the public key is the command's output
    return 0


def _provision_store(config: OperatorConfig) -> int:
    LiveSessionStore.provision(
        config.store_path,
        config.network,
        config.provider_identity_xonly,
        config.handshake_policy(),
        config.authority_declaration(),
        custody_recipient=config.custody_recipient,
    )
    return 0


def _inspect_swaps(
    config: OperatorConfig, crypto: Context, custody: str, args: argparse.Namespace
) -> None:
    """Inspect the authoritative store offline, never construct live backends."""
    with LiveSessionStore.acquire(
        config.store_path,
        config.network,
        config.provider_identity_xonly,
        config.handshake_policy(),
        crypto=crypto,
        custody_identity=custody,
        public_keys=crypto,
    ) as store:
        page = store.inspect_swaps(session_id=args.session_id, after=args.after, limit=args.limit)
    print(  # noqa: T201 - explicit operator output, no secret material
        json.dumps(
            {
                "format": "rillswap/provider-swap-inspection/v1",
                "action_authority": "none",
                **asdict(page),
            },
            sort_keys=True,
        )
    )


def _reconcile_payment(
    config: OperatorConfig, crypto: Context, custody: str, args: argparse.Namespace
) -> None:
    """Track one payment with read credentials; never run settlement or claims."""
    lnd = config.lnd
    if lnd is None:
        raise OperatorConfigError("payment reconciliation requires configured LND")
    with LiveSessionStore.acquire(
        config.store_path,
        config.network,
        config.provider_identity_xonly,
        config.handshake_policy(),
        crypto=crypto,
        custody_identity=custody,
        public_keys=crypto,
    ) as store:
        try:
            tracker = LndPaymentSender(
                host="127.0.0.1",
                port=lnd.port,
                tls_certificate_path=lnd.tls_certificate,
                macaroon_path=lnd.macaroon,
                network=config.network,
            )
        except ValueError:
            raise OperatorConfigError(
                "payment reconciliation requires a supported network"
            ) from None
        result = reconcile_payment(
            store, tracker, crypto, session_id=args.session_id, now=int(time.time())
        )
    print(  # noqa: T201 - explicit redacted operator output
        json.dumps(
            {
                "format": "rillswap/provider-payment-reconciliation/v1",
                **asdict(result),
            },
            sort_keys=True,
        )
    )


def _chain_tip(config: OperatorConfig) -> Callable[[], int] | None:
    core = config.bitcoin_core
    if core is None:
        return None
    try:
        reader = CoreTransactionReader(
            port=core.port, cookie_path=core.cookie_file, network=config.network
        )
    except ValueError:
        raise OperatorConfigError("bitcoin_core requires a supported network") from None
    return reader.tip_height


def _claim_fee(config: OperatorConfig) -> Callable[[], ClaimFeeRate] | None:
    """Return node pricing for automatic claims or opted-in network charges."""
    core = config.bitcoin_core
    if core is None or (
        config.terms.network_fees is None
        and (
            config.handshake.profile != "ln-to-btc/v1"
            or config.quote.claim_fee_reserve_sat is not None
        )
    ):
        return None
    try:
        reader = CoreTransactionReader(
            port=core.port,
            cookie_path=core.cookie_file,
            network=config.network,
            max_fee_estimate_sat_vb=core.max_fee_estimate_sat_vb,
        )
    except ValueError:
        raise OperatorConfigError("bitcoin_core requires a supported network") from None

    def sample() -> ClaimFeeRate:
        fee = reader.next_block_fee()
        return ClaimFeeRate(rate_sat_kvb=fee.rate_sat_kvb, floor_sat_kvb=fee.floor_sat_kvb)

    return sample


def _payment_sender(config: OperatorConfig) -> LndPaymentSender | None:
    lnd = config.lnd
    if lnd is None or lnd.payment_macaroon is None:
        return None
    try:
        return LndPaymentSender(
            host="127.0.0.1",
            port=lnd.port,
            tls_certificate_path=lnd.tls_certificate,
            macaroon_path=lnd.payment_macaroon,
            network=config.network,
        )
    except ValueError:
        raise OperatorConfigError("settlement requires a supported network") from None


def _liquidity(config: OperatorConfig) -> Callable[[], int] | None:
    """Return what this profile pays out from, read by the announcement cap.

    LN payouts (btc-to-ln, erc20-to-ln) are bounded by the best single channel,
    LN to BTC by the Core funding wallet, which also gates each firm quote
    (even with ``follow_liquidity`` off). LN to ERC20 has no token balance
    source yet, so its configured bands stay as they are.
    """
    profile = config.handshake.profile
    if profile in ("btc-to-ln/v1", "erc20-to-ln/v1"):
        sender = _payment_sender(config)
        return None if sender is None else sender.largest_channel_send_sat
    wallet = _core_wallet(config) if profile == "ln-to-btc/v1" else None
    return None if wallet is None else wallet.trusted_balance_sat


def _core_wallet(config: OperatorConfig) -> CoreTransactionReader | None:
    core = config.bitcoin_core
    if core is None:
        return None
    try:
        return CoreTransactionReader(
            port=core.port, cookie_path=core.cookie_file, network=config.network, wallet=core.wallet
        )
    except ValueError:
        raise OperatorConfigError("bitcoin_core requires a supported network") from None


def _liquidity_sample(config: OperatorConfig) -> LiquiditySampler | None:
    """Return the cached balance read that prices ``dynamic_fees`` discounts.

    The LND channel position is an interval: in-flight HTLCs count as gone at
    its low end and as returned at its high end. The reserve is the Core
    wallet (trusted to trusted plus pending) or the EVM signer's token
    balances. Config validation guarantees every backend named here.
    """
    lnd, evm = config.lnd, config.evm
    if config.dynamic_fees is None or lnd is None:
        return None
    if config.handshake.profile in EVM_PROFILES:
        if evm is None:
            return None
        settings = evm

        def reserves() -> dict[str, tuple[int, int]]:
            return {token: (base, base) for token, base in evm_token_balances(settings).items()}

    else:
        wallet = _core_wallet(config)
        if wallet is None:
            return None
        core = wallet

        def reserves() -> dict[str, tuple[int, int]]:
            return {BTC_RESERVE: core.balance_interval_sat()}

    channels = lnd

    def read() -> LiquiditySample:
        response = lnd_channel_balance(channels)
        local, remote, outgoing, incoming = (
            channel_amount_msat(response, field) // 1000
            for field in (
                "local_balance",
                "remote_balance",
                "unsettled_local_balance",
                "unsettled_remote_balance",
            )
        )
        return LiquiditySample(
            outbound_low_sat=local,
            outbound_high_sat=local + outgoing + incoming,
            capacity_sat=local + remote + outgoing + incoming,
            reserves=reserves(),
        )

    return LiquiditySampler(read)


def _evm_settlement(
    config: OperatorConfig, store: LiveSessionStore, crypto: Context
) -> EvmSettlementEngine | None:
    """Build the RS-010 engine for an EVM-profile process; None for Bitcoin profiles."""
    evm, profile = config.evm, config.handshake.profile
    if evm is None or profile not in EVM_PROFILES:
        return None
    htlc = EvmHtlcClient(
        rpc_url=evm.rpc_url,
        chain_id=evm.chain_id,
        htlc_contract=evm.htlc_contract,
        signer_private_key=read_evm_signer_key(evm.signer_key_file),
    )
    try:
        htlc.verify_deployment()  # refuse at startup, never mid-swap
    except EvmBackendError as error:
        raise OperatorConfigError(f"EVM HTLC deployment refused: {error}") from None
    tip = _chain_tip(config)
    if tip is None:
        raise OperatorConfigError("EVM profiles need bitcoin_core for the Bitcoin tip")
    return EvmSettlementEngine(
        store,
        htlc,
        crypto,
        assets=evm.assets(),
        rates=evm.rates,
        schedule=evm.schedule(),
        btc_tip=tip,
        lightning=_payment_sender(config),
        hold_invoices=_hold_invoices(config),
        normal_fee_sat=functools.partial(
            normal_service_fee, config.terms.base_fee_sat, config.terms.proportional_millionths
        ),
        claim_address=evm.claim_address,
        quote_pricing=_evm_pricing(config, htlc),
    )


def _evm_pricing(
    config: OperatorConfig, htlc: EvmHtlcClient
) -> Callable[[], EvmQuotePrices] | None:
    """Build an opt-in live USD/gas snapshot; never contact a feed at startup."""
    evm = config.evm
    if evm is None or evm.pricing is None:
        return None
    pricing = evm.pricing
    tokens = evm.tokens
    side: Side = (
        "provider_sells_btc"
        if config.handshake.profile == "erc20-to-ln/v1"
        else "provider_buys_btc"
    )
    feed = PriceFeed(pricing.mempool_url, proxy=config.relay_proxy, with_eth=True)

    def observe() -> EvmQuotePrices:
        gas_price = htlc.gas_price_wei()
        if type(gas_price) is not int or not 0 < gas_price <= pricing.max_gas_price_wei:
            raise PriceUnavailableError("EVM gas price exceeds the quote limit")
        # Price freshness is checked after the gas RPC, not before a slow read.
        prices = feed.prices()
        rates, gas = {}, {}
        for token in tokens:
            rate = rate_token_base_per_btc(prices, side, token.token_decimals)
            if rate <= 0:
                raise PriceUnavailableError("stablecoin rate is below one base unit")
            gas[token.token_contract] = gas_wei_as_token_base(
                prices, pricing.gas_units * gas_price, token.token_decimals
            )
            rates[token.token_contract] = rate
        return EvmQuotePrices(rates, gas)

    return observe


def _settlement(
    config: OperatorConfig, store: LiveSessionStore, crypto: Context
) -> SettlementEngine | None:
    lnd, core = config.lnd, config.bitcoin_core
    if lnd is None or core is None or lnd.payment_macaroon is None:
        return None
    if config.handshake.profile in EVM_PROFILES:
        return None  # the EVM engine owns this process's swaps
    try:
        chain = CoreTransactionReader(
            port=core.port,
            cookie_path=core.cookie_file,
            network=config.network,
            wallet=core.wallet,
            max_fee_estimate_sat_vb=core.max_fee_estimate_sat_vb,
        )
    except ValueError:
        raise OperatorConfigError("settlement requires a supported network") from None
    lightning = _payment_sender(config)
    assert lightning is not None  # noqa: S101 - payment_macaroon checked above
    # Regtest Core rarely has a fee estimate; its relay/mempool floors and the
    # configured claim floor then price cooperative claims. Public networks
    # always require an affirmative conservative estimate.
    settings = EngineSettings(allow_regtest_fixed_fee=config.network.name == "regtest")
    return SettlementEngine(
        store, chain, lightning, crypto, settings, hold_invoices=_hold_invoices(config)
    )


def _hold_invoices(config: OperatorConfig) -> LndHoldInvoices | None:
    lnd = config.lnd
    if lnd is None or lnd.invoices_macaroon is None:
        return None
    try:
        return LndHoldInvoices(
            host="127.0.0.1",
            port=lnd.port,
            tls_certificate_path=lnd.tls_certificate,
            macaroon_path=lnd.invoices_macaroon,
            network=config.network,
        )
    except ValueError:
        raise OperatorConfigError("lnd requires a supported network") from None


def _invoice_decoder(config: OperatorConfig) -> Callable[[str], InvoiceBinding] | None:
    lnd = config.lnd
    if lnd is None:
        return None
    try:
        decoder = LndInvoiceDecoder(
            host="127.0.0.1",
            port=lnd.port,
            tls_certificate_path=lnd.tls_certificate,
            macaroon_path=lnd.macaroon,
            network=config.network,
        )
    except ValueError:
        raise OperatorConfigError("lnd requires a supported network") from None
    return decoder.decode


def _warn_on_a_mainnet_fee_ceiling(config: OperatorConfig) -> None:
    """Warn that a ceiling underprices mainnet fees; it is for skewed estimators like signet's."""
    core = config.bitcoin_core
    if config.network.name != "mainnet" or core is None or core.max_fee_estimate_sat_vb is None:
        return
    logging.getLogger(__name__).warning(
        "bitcoin_core.max_fee_estimate_sat_vb caps Core's mainnet fee estimates at %d sat/vB: "
        "in a fee spike, funding, claim fee reserves, claims and refunds start below the "
        "next-block rate and may confirm late",
        core.max_fee_estimate_sat_vb,
    )


async def _serve(config: OperatorConfig, crypto: Context, custody: str) -> None:
    try:
        require_supported_network(config.network)
    except ValidationError:
        raise OperatorConfigError("network is not supported for serving") from None
    lnd = config.lnd
    _warn_on_a_mainnet_fee_ceiling(config)
    if (
        config.network.name != "regtest"
        and config.provider_destination_script is not None
        and (lnd is None or lnd.payment_macaroon is None or config.bitcoin_core is None)
    ):
        # Firm offers invite funding; without settlement nothing would pay them.
        raise OperatorConfigError("firm offers need lnd.payment_macaroon and bitcoin_core")
    if (
        config.provider_destination_script is not None
        and config.handshake.profile == "ln-to-btc/v1"
        and (lnd is None or lnd.invoices_macaroon is None or config.bitcoin_core is None)
    ):
        # LN to BTC firm offers open hold invoices and fund contracts.
        raise OperatorConfigError(
            "ln-to-btc firm offers need lnd.invoices_macaroon and bitcoin_core"
        )
    if config.handshake.profile in EVM_PROFILES:
        # RS-010 profiles pay (erc20-to-ln) or hold (ln-to-erc20) on LND, lock on
        # the EVM chain, and read the Bitcoin tip for cross-chain timing.
        needed = (
            "payment_macaroon"
            if config.handshake.profile == "erc20-to-ln/v1"
            else ("invoices_macaroon")
        )
        if (
            config.evm is None
            or config.bitcoin_core is None
            or lnd is None
            or getattr(lnd, needed) is None
        ):
            raise OperatorConfigError(
                f"{config.handshake.profile} needs evm, bitcoin_core and lnd.{needed}"
            )
    try:
        proxy = require_relay_route(
            config.network, config.relay_proxy, allow_direct=config.allow_direct_relays
        )
        # Onion relays are opportunistic: without the proxy they are skipped, so
        # they are neither connected nor announced (service_policy drops them too).
        relays = reachable_relays(config.relay_urls, proxy)
        for url in relays:  # refuse at startup, not in the reconnect loop
            RelayConnection(url, proxy=proxy)
    except RelayError as error:
        raise OperatorConfigError(str(error)) from None
    if not relays:
        raise OperatorConfigError("onion relays need the relay proxy, and no other relay is set")
    if len(relays) < len(config.relay_urls):
        logging.getLogger(__name__).info(
            "no relay proxy: skipping %d onion relays", len(config.relay_urls) - len(relays)
        )
    identity = ProviderIdentity.load(
        config.identity_file,
        custody_identity=custody,
        expected_xonly_public_key=config.provider_identity_xonly,
        crypto=crypto,
    )
    notifications = config.notifications
    async with notification_sender(notifications, proxy) as sender:  # closed after the last events
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(signum, stop.set)
        with LiveSessionStore.acquire(
            config.store_path,
            config.network,
            config.provider_identity_xonly,
            config.handshake_policy(),
            crypto=crypto,
            custody_identity=custody,
            public_keys=crypto,
            max_sessions=config.max_sessions,
            max_tombstones=config.max_tombstones,
            max_active_reservations=config.max_active_reservations,
            new_sessions_per_minute=config.new_sessions_per_minute,
        ) as store:
            service = HandshakeService(
                store,
                identity,
                crypto,
                config.service_policy(),
                chain_tip=_chain_tip(config),
                invoice_decoder=_invoice_decoder(config),
                settlement=_settlement(config, store, crypto),
                hold_invoices=_hold_invoices(config),
                evm_settlement=_evm_settlement(config, store, crypto),
                liquidity=_liquidity(config),
                claim_fee=_claim_fee(config),
                liquidity_sample=_liquidity_sample(config),
            )
            if notifications is None or sender is None:
                await service.run(stop)
                return
            notifier = Notifier(
                notifications,
                sender,
                store,
                profile=config.handshake.profile,
                network=config.network.name,
                health=service.health,
                balances=balance_readers(config) if notifications.summary_balances else None,
            )
            notifier.start()
            failed = True
            try:
                await service.run(stop)
                failed = False
            finally:
                await notifier.close(failed=failed)  # while the store is still held


async def _test_notification(config: OperatorConfig) -> int:
    """Explicitly test the configured route without opening financial state."""
    settings = config.notifications
    if settings is None:
        raise OperatorConfigError("notifications are not configured")
    proxy = require_relay_route(
        config.network, config.relay_proxy, allow_direct=config.allow_direct_relays
    )
    try:
        async with notification_sender(settings, proxy) as sender:
            if sender is None:
                raise OperatorConfigError(  # noqa: TRY301 - explicit configuration refusal
                    "notification sender unavailable"
                )
            accepted = await sender.send(
                f"RillSwap {config.handshake.profile} ({config.network.name}): notification test",
                "Operator-requested notification test. No swap was started.",
                warning=False,
            )
    except OperatorConfigError:
        raise
    except Exception as error:  # noqa: BLE001 - never echo service URLs or upstream errors
        diagnostic(
            logging.getLogger(__name__),
            "notification.test_failed",
            "Notification test failed",
            level=logging.WARNING,
            error_type=type(error).__name__,
        )
        return REFUSED
    diagnostic(
        logging.getLogger(__name__),
        "notification.test",
        "Notification test finished",
        delivery_status="accepted" if accepted else "failed",
    )
    return 0 if accepted else REFUSED


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rill-provider", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("provision-identity", help="create a new identity file")
    identity.add_argument("--out", type=Path, required=True)
    identity.add_argument("--recipient", required=True, help="age X25519 recipient")
    identity.add_argument("--native-crypto-library", type=Path, required=True)
    for name, text in (
        ("provision-store", "create a new empty live session store"),
        ("serve", "run the handshake service until SIGINT/SIGTERM"),
        ("test-notification", "send an explicit test without opening the swap store"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True)
    inspection = commands.add_parser(
        "inspect-swaps", help="inspect bounded retained swap state offline"
    )
    inspection.add_argument("--config", type=Path, required=True)
    cursor = inspection.add_mutually_exclusive_group()
    cursor.add_argument("--session-id", help="inspect one exact session ID")
    cursor.add_argument("--after", help="resume after this session ID (exclusive)")
    inspection.add_argument("--limit", type=int, default=100, help="page size, 1 to 1000")
    reconciliation = commands.add_parser(
        "reconcile-payment", help="track one PAYING swap without sending"
    )
    reconciliation.add_argument("--config", type=Path, required=True)
    reconciliation.add_argument("--session-id", required=True)
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING"))
    parser.add_argument("--log-format", default="text", choices=("text", "json"))
    return parser


def _configure_logging(level: str, log_format: str = "text") -> None:
    configure_logging(level, log_format=log_format)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one operator command; return the process exit status."""
    args = _parser().parse_args(argv)
    _configure_logging(args.log_level, args.log_format)
    try:
        if args.command == "provision-identity":
            return _provision_identity(args)
        config = load_config(args.config)
        if args.command == "test-notification":
            return asyncio.run(_test_notification(config))
        if args.command == "provision-store":
            return _provision_store(config)
        custody = read_custody_identity(config.custody_identity_file)
        with _context(config.native_crypto_library) as crypto:
            if args.command == "inspect-swaps":
                _inspect_swaps(config, crypto, custody, args)
            elif args.command == "reconcile-payment":
                _reconcile_payment(config, crypto, custody, args)
            else:
                with diagnostic_context(
                    network=config.network.name, profile=config.handshake.profile
                ):
                    diagnostic(logging.getLogger(__name__), "service.starting", "Starting provider")
                    asyncio.run(_serve(config, crypto, custody))
                    diagnostic(logging.getLogger(__name__), "service.stopped", "Provider stopped")
    except (
        OperatorConfigError,
        LiveSessionStoreError,
        ProviderIdentityError,
        LndObservationError,
    ) as error:
        print(f"rill-provider: {error}", file=sys.stderr)  # noqa: T201
        return REFUSED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
