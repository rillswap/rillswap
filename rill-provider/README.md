# rill-provider

`rill-provider` runs the provider (maker) side of RillSwap. It announces swap
terms over Nostr relays, handles client sessions, and coordinates Bitcoin,
Lightning and ERC20 settlement using your own nodes.

It is for operators running a self-hosted liquidity provider, not a hosted
service. Running it requires node credentials, liquidity, and careful
handling of encrypted keys and persistent swap state.

## Install

Use a checkout of this monorepo, Python 3.13 or later (CI uses 3.14), `uv`,
and CMake with a C compiler. From `rill-provider/`:

```sh
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
source .venv/bin/activate
cmake -S ../rill-crypto -B tmp/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build tmp/native --parallel 2
```

Set `native_crypto_library` in your provider config to the absolute path of
`tmp/native/librill_crypto.so` (the Linux build output). Identity
provisioning takes the same path through `--native-crypto-library`.

## Quick start

For the easiest trial, use the disposable Docker stack: from the repository
root run `dev/devctl up`, then `dev/devctl smoke`. See
[DEVELOPMENT.md](../DEVELOPMENT.md) for requirements and controls.

To run your own signet provider, first prepare synced local Bitcoin Core and
LND nodes, channel liquidity, scoped LND macaroons, `age-keygen`, and a Tor
`HTTPTunnelPort` (for example `HTTPTunnelPort 127.0.0.1:9080` in your Tor
configuration). Then, from `rill-provider/` with the environment above active:

```sh
mkdir -p -m 700 tmp/signet
age-keygen -o tmp/signet/custody.key
chmod 600 tmp/signet/custody.key
rill-provider provision-identity --out tmp/signet/provider-identity.age \
  --recipient "$(age-keygen -y tmp/signet/custody.key)" \
  --native-crypto-library "$PWD/tmp/native/librill_crypto.so"
cp examples/provider.signet.json tmp/signet/provider.json
```

Edit the copied config before starting:

- Set `provider_identity_xonly` to the public key printed by provisioning.
- Set `custody_recipient` to the output of `age-keygen -y`.
- Set the absolute native library path and your node credential paths.
- Replace the example destination script with your own P2WPKH or P2TR
  scriptPubKey hex.
- Replace the relay URL, amount bands and fees.
- Only affirm the store authority declarations if they are true.

The example serves BTC to Lightning; see [Swap profiles](#swap-profiles) for
the others. Relative file paths resolve from the config file's directory.

```sh
rill-provider provision-store --config tmp/signet/provider.json
rill-provider serve --config tmp/signet/provider.json
```

Provision the store once and run one service per store. Stop with SIGINT or
SIGTERM. Never restore an older store snapshot.

## Docker

CI publishes `ghcr.io/rillswap/rill-provider` for amd64 and arm64. It holds
`rill-provider`, the `rill` CLI, the native crypto library and a Tor client,
and runs as uid 1000. `latest` follows `main`; in production, pin an image
digest, a `sha-<full commit hash>` tag, or a version tag such as `1.2.3` from
a `v1.2.3` release.

[docker/compose.yaml](docker/compose.yaml) runs one service per swap profile
(`btc-to-ln`, `ln-to-btc`, `erc20-to-ln`, `ln-to-erc20`), each with its own
store, identity and custody key, plus one shared Tor client that offers only
an HTTP tunnel inside the Compose network. Core and LND stay on your host or
network; the containers reach them through the hosts set in `.env`.

1. In an empty directory, fetch the compose file and the environment
   template, then edit `.env` (profiles, Core and LND addresses, uid):

   ```sh
   base=https://raw.githubusercontent.com/rillswap/rillswap/main/rill-provider/docker
   curl -fsSLO "$base/compose.yaml"
   curl -fsSL -o .env "$base/example.env"
   install -d -m 0700 makers stores credentials
   ```

   Core and LND must accept connections from the Docker network: set Core's
   `rpcbind` and `rpcallowip` and LND's `rpclisten` accordingly.

2. Put the LND credentials in `./credentials`, readable by the container
   uid: `tls.cert` (it must be valid for `127.0.0.1`, as LND's generated
   certificate is) and the `read`, `payment` and `invoices` macaroons from
   [LND credentials](#lnd-credentials). Then create the Core credential:

   ```sh
   docker compose run --rm setup rill-provider-init core-credential
   ```

   It writes `credentials/core.cookie` and prints an `rpcauth` line for the
   `__cookie__` user, plus an optional `rpcwhitelist` limited to the methods
   the provider calls. Add them to `bitcoin.conf` and restart Core. This works
   alongside existing `rpcuser`/`rpcpassword` or `rpcauth` logins.

3. Create each maker. Bitcoin profiles need a destination scriptPubKey from
   your wallet (`bitcoin-cli getaddressinfo <address>` shows it); LN to BTC
   also needs the Core wallet that funds swaps:

   ```sh
   docker compose run --rm setup rill-provider-init maker --profile ln-to-btc \
     --network signet --destination-script 0014... --core-wallet rillswap \
     --affirm-store-authority
   ```

   Pass `--affirm-store-authority` only when `./stores` is outside every
   backup and snapshot restore domain and used by one host; stores refuse to
   open without that attestation. Review `makers/<profile>/provider.json`
   (amount bands, fees, relays, `quote`). ERC20 makers print an EVM signer
   address to fund with gas, and their `evm` section must be completed
   (every `REPLACE` and zero value) before the store can be provisioned.

4. Provision each store once, then start:

   ```sh
   docker compose run --rm --no-deps ln-to-btc \
     rill-provider provision-store --config /rill/config/provider.json
   docker compose up -d
   docker compose ps
   ```

   A maker turns healthy once Core, LND and the Tor tunnel answer.

5. Optionally, enable [notifications](#notifications) for a maker: write its
   Apprise URLs to `makers/<profile>/notify.urls` (mode 0600, owned by the
   container uid), add a `notifications` section with
   `"urls_file": "notify.urls"` to its `provider.json`, and run
   `docker compose up -d` again. Notifications go through the shared Tor
   client, so only HTTP services work (onion URLs too); add
   `"use_tor": false` for a service on your LAN.

Back up `./makers` (custody keys, identities, configs). Never back up,
restore or copy `./stores`; `./credentials` can be recreated. For offline
commands, stop the maker first and use the same mounts, for example
`docker compose stop ln-to-btc` and then `docker compose run --rm --no-deps
ln-to-btc rill-provider inspect-swaps --config /rill/config/provider.json`.
Upgrade with `docker compose pull && docker compose up -d`.

To build the image from a checkout, run
`docker build -f rill-provider/docker/Dockerfile -t rill-provider .` at the
repository root and check it with `rill-provider/docker/smoke-test.sh
rill-provider`. Third-party dependencies are hash-locked in
`docker/requirements.txt`; regenerate the locks with `docker/lock.sh`.

## Commands

| Command | Purpose |
| --- | --- |
| `provision-identity` | Create an encrypted provider identity file |
| `provision-store` | Create a new empty live session store |
| `serve` | Run the provider until SIGINT or SIGTERM |
| `inspect-swaps` | Inspect retained swap state offline |
| `reconcile-payment` | Track one `PAYING` swap without sending another payment |

Use `rill-provider <command> --help` for arguments. All commands except
`provision-identity` require `--config`. Refused operations exit with status
2 and a redacted error.

## Configuration

Start from [examples/provider.signet.json](examples/provider.signet.json).
The configuration is strict JSON; unknown fields are refused.

| Field | What to configure |
| --- | --- |
| `network` | Complete Bitcoin network identity, not just a network name |
| `provider_identity_xonly`, `identity_file` | Provisioned public identity and encrypted identity file |
| `store_path` | Authoritative live SQLite store |
| `custody_recipient`, `custody_identity_file` | Age recipient and matching private custody key file |
| `native_crypto_library` | Path to the built native crypto library |
| `bitcoin_core` | Loopback RPC `port`, `cookie_file`, optional `wallet` and `max_fee_estimate_sat_vb` |
| `lnd` | Loopback gRPC `port`, `tls_certificate` and scoped macaroon paths |
| `provider_destination_script` | Provider's P2WPKH or P2TR destination script; enables Bitcoin firm offers |
| `handshake` | Selected profile, encryption suites and capabilities |
| `terms` | Advertised profiles, amount bands, fees, slot label and the liquidity cap (`follow_liquidity`, `liquidity_margin_percent`) |
| `quote` | Confirmation requirements, fee caps, deadlines and timing budgets |
| `authority` | Store volume label and deployment attestations |
| `relay_urls`, `relay_proxy` | Relay WebSocket URLs and loopback Tor HTTP tunnel |
| `evm` | ERC20 chain, verified HTLC deployment, signer, tokens and timing settings |
| `dynamic_fees` | Optional private balance-aware discounts ([details](#balance-aware-discounts)) |

`terms.amount_bands` are in satoshis. Fees use `base_fee_sat` and
`proportional_millionths`. Review the `quote` settings against your network
and liquidity instead of treating the defaults as guarantees.

With `terms.follow_liquidity` (default `true`), the provider announces and
accepts at most what it can pay out, less a random margin from
`terms.liquidity_margin_percent` (default `[10, 20]`), and never more than the
configured bands. Each announcement (every 30 minutes) checks the payout
liquidity again: the largest single LND channel's sendable balance for BTC to
LN and ERC20 to LN, or the funding wallet's trusted balance for LN to BTC. LN
to ERC20 keeps its configured bands. The configured maximum applies whenever
liquidity is at least `maximum / (1 - high margin)`; keep more than that to
reveal nothing about your balance. Below it, a fresh margin is drawn when
liquidity falls under the announced maximum (swaps, or a wallet drained
outside the provider) or grows past `cap / (1 - high margin)`; otherwise the
cap stays. Changes wait for the next scheduled announcement, so balance
changes are not published as they happen. Below the smallest band, the
provider stops announcing until liquidity recovers. If the source fails, the
last cap stays (the configured bands before any reading). The Docker template
uses one band of 10,000 to 10,000,000 sat.

New Docker configurations charge a 100 sat base plus 0.1 % for BTC to LN,
or 0.5 % for LN to BTC. Network costs are separate when `terms.network_fees`
is enabled. Existing configurations are never overwritten by setup; update
their service fees explicitly if desired.

A request the provider can no longer fill between announcements is refused
at quote time with `capacity_unavailable`, before the client pays anything:
BTC to LN and ERC20 to LN need a payable route to the invoice, and LN to BTC
needs a wallet balance covering the contract plus `quote.max_funding_fee_sat`
before a hold invoice is opened. The LN to BTC check also applies with
`follow_liquidity` off; while the balance cannot be read, quotes are admitted
as before. LN to ERC20 does not check its token balance. Concurrent quotes
each see the whole balance.

LN to BTC reads the balance with Core's `getbalances`. If your
`rpcwhitelist` does not include `getbalances`, add it and restart Core;
until then the provider logs `liquidity unavailable` and `funding
balance unavailable`, keeps the configured bands, and does not check firm
quotes against the balance.

### LN to BTC funding

The provider funds each contract at Core's economical next-block estimate
(`estimatesmartfee 2 ECONOMICAL`, Core's closest setting to "next block"),
lowered to `bitcoin_core.max_fee_estimate_sat_vb` when set, and never below
the node's `minrelaytxfee` or current `mempoolminfee`. Without an estimate
it refuses to fund rather than guess (regtest alone falls back to the node
minimum), and the swap is retried later. The ceiling is never used as a
fallback rate.

It picks the inputs itself, for privacy: the fewest coins that pay the
contract, then, among those, the set leaving the least excess. Confirmed
coins come first; safe unconfirmed change only when they are not enough.
Core adds no other inputs, and when the excess is not worth a change output,
Core adds it to the fee instead. Only single-key coins whose signed size is
known (P2TR key path, P2WPKH, P2SH-P2WPKH, P2PKH) are candidates. Run one
provider per funding wallet.

This needs Core's `listunspent`. If your `rpcwhitelist` does not include
`listunspent`, add it and restart Core; until then the provider logs a warning and lets Core pick the inputs, at the same rate.

### LN to BTC claim fee reserve

The contract holds the payout plus a claim fee reserve. The client's claim
pays exactly the reserve as its fee, so the destination receives exactly the
requested amount. Unless `quote.claim_fee_reserve_sat` is set, the provider
prices the reserve for each quote: the larger script-path claim to the
client's destination at the same next-block rate it funds with (the node's
relay and mempool minimum is only a lower bound), so the cooperative claim
pays at least that rate too, and never below the client's requested minimum.
Indicative quotes assume a P2TR destination. Fees are sampled once per tick (15 seconds), never
per request. Without a sample, or when the reserve would exceed
`quote.max_claim_fee_sat`, LN to BTC quotes answer `capacity_unavailable`. A
client asking for a minimum reserve above `quote.max_claim_fee_sat` gets
`limits_unsatisfiable`, since no claim could spend it. A cooperative claim
paying exactly the signed reserve is admitted once it meets the node's relay
and mempool minimum, even if fees rose after signing.

If your configuration does not set `claim_fee_reserve_sat` (the examples and
`rill-provider-init` never did), the upgraded provider switches from the former
fixed 1,000 sat default to automatic pricing; swaps already signed keep their
reserve. Set it to keep a fixed reserve instead.

### Dynamic Bitcoin network fees

Opt in by adding this object under `terms` in a Bitcoin provider's config:

```json
"network_fees": {
  "max_feerate_sat_kvb": 10000,
  "max_routing_fee_ppm": 1000
}
```

The example caps quoted estimates at 10 sat/vB. The signed offer keeps
`base_fee_sat` and `proportional_millionths` as service pricing and advertises
both new limits. Each request samples Core's next-block estimate and adds
`ceil(154 * rate_sat_kvb / 1000)` sat: a cooperative one-input, two-P2TR-output
transaction. Actual wallet/input costs can differ; the provider absorbs that
difference. The client's reverse claim reserve is separate and unchanged.

Quotes commit the selected signed offer, fee breakdown and **60-second
acceptance expiry**. Clients verify the formula and cap the rate independently
(currently at twice their own trusted node/API estimate, also bounded by the
advertised ceiling and their total fee limit). A provider cannot change the
size or introduce an unadvertised multiplier. Quotes may be refused when
estimators disagree or estimates are unavailable; missing evidence never means
an unlimited fee. Accepted prices do not change after a spike or restart.

Routing remains inside the service fee. Provider-originated Lightning payments
use no more than the advertised principal-based ppm budget, the service fee,
or the existing absolute operator cap (whichever is lowest). The mining charge
cannot be spent as a routing allowance. This does not cap the client's wallet
fees for paying a reverse invoice.

**Upgrade:** absent `network_fees` keeps existing behavior and stores unchanged.
Enabling it changes the immutable handshake policy: drain the old provider,
retain its store/recovery material, choose a new `store_path` and explicitly
run `provision-store`. Do not copy or reset the old store. Disabling it on the
new store is also refused. Update clients and recovery tools first: old tools
fail closed on the new required feature. Pricing coefficient changes alone do
not require a new store, but requests bound to the previous policy are refused
rather than silently repriced.

Only featured offers have a client-verified service/network formula. Legacy
prices remain indicative, protected by the client's total cap and the browser's
review step when the firm price exceeds its preview.

For a fresh disposable dev stack, `RILL_DEV_NETWORK_FEES=1` opts only the two
Bitcoin configs into this pricing model during bootstrap. It never edits an
existing config or store. Compose CI runs separate legacy and fee-enabled
variants, including real CLI/browser swaps in both Bitcoin directions.

### Balance-aware discounts

A provider that keeps liquidity on both sides can discount the swaps that
rebalance it, even below zero, so that arbitrageurs do the rebalancing. Opt in
with a top-level `dynamic_fees` object (never announced):

```json
"dynamic_fees": {
  "btc_reserve_target_sat": 5000000,
  "min_service_fee_ppm": -1000,
  "rebate_budget_sat_24h": 100000
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `btc_reserve_target_sat` | required on Bitcoin profiles | soft minimum of the `bitcoin_core` wallet |
| `stable_reserve_target_usd` | required on EVM profiles | soft minimum of each token pool, at 1 USD per token |
| `min_service_fee_ppm` | `-1000` (-0.1 %) | lowest service fee, in millionths of the principal (-10000 to 0) |
| `rebate_budget_sat_24h` | `100000` | rebates this process may grant per 24 hours |

The curve keeps Lightning outbound liquidity inside 45 to 55 % of channel
capacity (inbound is the rest) and each reserve above its target. A swap that
repairs a shortage is discounted by how much it repairs; every other swap pays
the advertised fee, never more. The discount applies to the service fee only:
the network fee is charged on top and never discounted. A rebate shows as
negative revenue in the swap ledger and notification summaries. For LN to BTC
the rebate lowers the hold invoice, so the provider funds more on-chain than it
receives over Lightning.

Safeguards:

- **Round trips:** the floor may not be deeper than this process's
  `proportional_millionths`. If several processes share one LND node, keep
  every floor no deeper than the smallest proportional fee among them, so a
  rebate cannot exceed the opposite direction's normal proportional fee.
  Align reserve targets across paired processes too. Stale observations or
  inconsistent targets can still subsidize a round trip; the rebate budget
  caps negative service fees, not a guarantee of zero arbitrage profit.
- **Budget:** rebates of open firm offers and of swaps completed in the last 24
  hours count against `rebate_budget_sat_24h`, checked inside each quote's own
  store transaction. Each process has its own budget. When it is spent,
  discounts stop at a zero service fee. This is not a total-loss limit:
  Lightning routing still uses the normal service-fee budget and may cost
  more than the discounted service charge; gas execution costs can drift too.
- **Unknown state:** balances are read as intervals (in-flight HTLCs, unconfirmed
  wallet coins and this process's open offers) and the end worse for the trader
  is priced. Any failed or incomplete read prices the normal fee.
- **Privacy:** discounts move in coarse steps (0.025 % of the principal,
  rounded down to whole sats, at least 1 sat). Balance reads are cached for
  15 seconds, and a refused rebate looks like any other capacity refusal.
  Prices necessarily reveal rebalancing incentives; adaptive quote probing
  can infer more. This reduces leakage but does not guarantee balance secrecy.
- **Griefing:** an open offer holds its rebate until its reservation is
  released (an unfunded offer's idle session is retired after
  `handshake_timeout`). A client that never funds its offers can temporarily
  exhaust the budget, bounded by `max_active_reservations` and session
  admission limits. Normal fees are never raised.

Requirements: a positive `base_fee_sat` and `lnd` (for channel balances).
Bitcoin profiles also need `terms.network_fees`, whose signed breakdown lets
clients check that the discounted service fee stays below the advertised one.
The BTC reserve is the `bitcoin_core` wallet: point a BTC to LN provider's
`provider_destination_script` at an address of the wallet the LN to BTC
provider funds from, and both share one reserve. EVM profiles must serve only
USD stablecoins; their reserve is the token balance of the funding signer, or
the forward maker's configured claim recipient. For live conversion and
separately charged gas, use [live stablecoin pricing](#live-stablecoin-pricing).
Legacy fixed rates also remain supported.

To share a token pool without sharing keys, set `evm.claim_address` in the
ERC20 to LN process to the LN to ERC20 maker's funding address. Forward claims
pay that address directly; the forward signer pays gas and needs no token
balance. The reverse process keeps its own signer and omits `claim_address`
(it is refused outside ERC20 to LN). Use a lowercase, nonzero address whose
key you control. Cooperative refunds require the recipient's signature; the
forward gas signer cannot authorize them when it uses a different key.
Changing this setting affects only new quotes: existing swaps and recovery
transactions retain the recipient in their signed terms. Omitting it keeps
the old signer-as-recipient behavior. Older releases refuse the new field.

Reading the BTC reserve uses Core's `getbalances`, as LN to BTC funding does; while a
backend read fails, the provider logs `liquidity sample unavailable` and
prices the normal fee.

Ordinary BTC-only LND responses include an open/pending-channel envelope even
when every custom commitment blob is empty; these envelopes are supported.
Nonempty custom blobs, malformed envelopes and auxiliary-parser JSON remain
unsupported and select the normal fee. This handling changes neither existing
stores nor credential permissions.

**Upgrade:** absent `dynamic_fees` keeps existing behavior. Enabling or
disabling it changes neither the handshake policy nor the store. An older
release refuses a config that contains it.

See the [balance-aware fee policy](../rill-docs/specs/extensions/balance-aware-fees.md)
for the curve, cost treatment and privacy limitations.

### BTC to LN claim fee

Without dynamic network pricing, the provider's claim fee comes out of its
success fee (`V = L + S`), so set
`terms.base_fee_sat` and `terms.proportional_millionths` to cover the claim
and routing: a swap whose success fee is below its claim fee loses money.
Every claim is priced for the cooperative key-path size (99 vB to a P2WPKH
destination, 111 vB to P2TR) at the node's own evidence for the signed
`quote.claim_confirmation_blocks` target: the highest of `minrelaytxfee`,
`mempoolminfee` and the conservative `estimatesmartfee`, lowered to
`bitcoin_core.max_fee_estimate_sat_vb` when set.

The cooperative claim is priced from a fresh sample when it is proposed. If
that fee exceeds the signed claim fee cap, the provider does not propose and
keeps the unilateral fallback. A script-path claim pays the same fee (or the
relay minimum for its larger size, if higher), and fee bumping raises it if it
stalls, up to the signed cap before the client can refund. Fallbacks prepared
for the cooperative window and deadline recovery never wait for Core: they use
the latest sample this process took (one is taken before paying each swap that
may cooperate). With no usable sample, a claim pays the signed cap rather than
risk the refund. A selected cooperative claim cannot be fee bumped.

After upgrading, claims no longer start at the former fixed 1,000 sat
minimum; claims and fallbacks already recorded keep their fees. LN to BTC
refunds keep their 1,000 sat minimum.

Admission limits include `max_sessions`, `max_tombstones`,
`new_sessions_per_minute` and `max_active_reservations`. The last one bounds
unreleased firm offers and accepted swaps (default 4). A swap holds its
reservation until the provider's claim reaches the settlement depth, so with
slow blocks the default fills quickly. When it is full, the provider answers
firm quotes with `capacity_unavailable` and logs `max_active_reservations
reached`.

`transport_pow_bits` (0 to 20, default 0 = off) requires RS-006 NIP-13 proof
of work on every message a client sends. The provider drops messages without
enough work after one hash, before any decryption. Each session keeps the
work it declared when it started, so you can change the value without
stranding swaps that are in progress. Clients that predate this setting can't
use an announcement that requires work, so enable it only after the clients
you serve support it. Each extra bit doubles the cost: 16 bits is about
65,000 hashes per message on average. In desktop Chromium on an HTTPS page,
that took about half a second per small message. Larger messages, phones, and
plain HTTP pages (no WebCrypto) take several times longer, and a swap sends
several messages. Work makes floods more expensive, but
it is not rate limiting or Sybil protection, because a native sender can
still produce messages much faster than a browser.

`bitcoin_core.max_fee_estimate_sat_vb` (1 to 10,000, unset by default) caps
Core's fee estimates. Use it where the estimator is skewed: on signet, a few
transactions paying hundreds of sat/vB next to empty blocks make
`estimatesmartfee` report over 200 sat/vB for 6 blocks. Without a cap, Lightning
to BTC funding then exceeds the signed `max_funding_fee_sat` and the swap waits
until its funding window closes, cooperative claims are refused because their
fee is below the estimate, and script-path claims start at the signed fee cap.
With a cap, funding pays at most the cap (never the cap in place of a missing
estimate), and claim, refund and cooperative fee checks use the capped
estimate. Core's relay and mempool minimum fees, the signed caps and
fee bumping are unchanged. On mainnet, leave it unset unless you understand
that a low cap also lowers the starting fee of your claims and refunds;
`serve` logs a warning at startup when it is set there. The
signet example and signet makers created by `rill-provider-init` set 2
sat/vB. Clients checking a cooperative claim against, or pricing a claim
fee reserve from, their own Core need the same cap (`rill swap btc-to-ln` or
`ln-to-btc --max-fee-estimate-sat-vb`).

### Swap profiles

Select one profile per deployment with `handshake.profile` and advertise it
in `terms.profiles`. The handshake policy is bound to the store when it is
provisioned; do not repurpose an existing store for another profile.

| Profile | Required settlement setup |
| --- | --- |
| `btc-to-ln/v1` | Bitcoin Core, provider destination script, LND payment macaroon, outbound Lightning liquidity |
| `ln-to-btc/v1` | Bitcoin Core funding wallet, provider destination script, LND payment and invoices macaroons, inbound Lightning liquidity |
| `erc20-to-ln/v1` | EVM settings, Bitcoin Core tip access, LND payment macaroon, outbound Lightning liquidity |
| `ln-to-erc20/v1` | EVM settings, Bitcoin Core tip access, LND invoices macaroon, token and gas liquidity |

For Lightning to BTC, change the example's `handshake.profile` to
`ln-to-btc/v1` and `terms.profiles` to `["ln-to-btc/v1"]`, add
`lnd.invoices_macaroon`, and set `bitcoin_core.wallet` to the Core wallet that
funds swaps. Keep the payment macaroon.

For ERC20 profiles, configure `evm` with `rpc_url`, `chain_id`, `name`,
`htlc_contract`, `block_seconds`, `signer_key_file` and `tokens`. Each token
needs its contract, symbol and decimals, plus either a fixed
`rate_token_base_per_btc` or live pricing below. Also set
`forward_timelock_delay_blocks`, `reverse_timelock_delay_blocks`,
`learn_and_claim_seconds` and `refund_and_ln_resolution_seconds`. Startup
verifies the Boltz ERC20Swap v6 deployment before serving.

The EVM signer file holds one hex secp256k1 private key, must be owned by the
service user, and must have owner-only permissions. Bitcoin profiles include
`cooperative-claim/v1` automatically; ERC20 profiles do not use it.

### Live stablecoin pricing

For USD stablecoins on chains whose gas currency is ETH, add this object under
`evm` and remove `rate_token_base_per_btc` from every token:

```json
"pricing": {
  "mempool_url": "https://mempool.example",
  "gas_units": 70000,
  "max_gas_price_wei": 200000000000
}
```

Replace the placeholder URL with your own HTTPS mempool instance.
`gas_units` is a required operator-chosen cost budget denominated in gas units,
not measured consumption or a transaction gas limit. The 70,000 example is
illustrative, not a guarantee: budget the claim for ERC20 to LN, and approval
plus lock for LN to ERC20. Choose it for your tokens and chain. On rollups,
L1 data charges are not included in `eth_gasPrice`; allow for them in the
budget. The provider absorbs execution-price changes and any extra recovery
or refund costs. Non-USD tokens and non-ETH gas currencies must use legacy
fixed pricing, with their costs covered by the configured success fee.

The provider values each token at exactly 1 USD (including a depegged token:
disable it yourself). BTC/USD comes from your mempool instance, checked
against Kraken within 2 %. Mempool observations must be at most one hour old;
Kraken BTC/USD and ETH/USD trades at most two minutes old. The BTC bound
worse for the trader determines the rate. Observations and failures are
cached for 30 seconds, never beyond source freshness. Requests use
`relay_proxy` when configured, including all price-feed traffic.

Each quote freezes its rate and gas charge before opening a reverse hold:

- ERC20 to LN: `ceil(service_sat * rate / 1e8) + gas_token_base`.
- LN to ERC20: `service_sat + ceil(gas_token_base * 1e8 / rate)`.

The gas charge is `gas_units * observed_gas_price_wei`, converted through
ETH/USD at 1 USD per token and rounded up. It is never discounted; a negative
service fee still reserves its full rebate budget even if gas makes the total
success fee positive. The signed success fee includes both charges, and the
client's total fee cap applies to their sum. EVM fees do not yet have a
client-verified service/network breakdown like Bitcoin fees do.

`max_gas_price_wei` defaults to 200 gwei and only refuses new quotes; it does
not cap execution, which could strand a funded claim. Missing, stale,
disagreeing or excessive price evidence refuses indicative and firm quotes,
never substitutes zero or falls back to a fixed rate. A cold price read may
take several seconds. Already accepted swaps do not depend on the feeds.

**Upgrade:** with `evm.pricing` absent, every token still needs its old fixed
rate and behaves as before. Live pricing with any fixed rate, or missing both
modes, is refused at startup. Enabling it changes no store or handshake
format and never reprices retained swaps. Older releases refuse this config.

### Funding confirmations

`quote.funding_confirmations` (default 1) is how many confirmations the
funding needs before the swap moves on. For BTC to LN it is how long you wait
on the client's deposit before paying the invoice. For Lightning to BTC it is
how long the client waits on your lockup before claiming; it must be at least
1. A Lightning to BTC client may choose to claim earlier, even from the
mempool (the CLI's `--claim-confirmations`, a web Settings field), and the
provider still cooperates: the client takes the double-spend risk, and your
own funding, unspent in your node's mempool, is enough evidence. ERC20
profiles use `evm.funding_confirmations` instead (EVM blocks, at least 1).
The value is signed into every offer and announced as
`rillswap/funding-confirmations`. The web app ranks providers by it by
default (fewest confirmations first, then lowest price) and labels the
fastest and cheapest offers. Clients refuse offers that wait longer than you
announced.

Upgrading: configurations that omit the field now wait 1 confirmation instead
of 2. Set `"funding_confirmations": 2` under `quote` to keep the old
behavior. Swaps already in progress keep the depth they signed.

#### Zero confirmations (BTC to LN only)

With `"funding_confirmations": 0` the provider pays the Lightning invoice as
soon as the exact contract output is unspent in its own node's mempool, before
any confirmation. This is fast for the client and risky for you:

- **The client can double-spend.** Until the deposit confirms, the client can
  replace it (RBF, or a conflicting transaction sent straight to miners) and
  spend the same inputs elsewhere. You have already paid the invoice and
  there is nothing left to claim: you lose the full swap amount.
- **Fee bumping is a race to the bottom.** You could spend the unconfirmed
  deposit in a child transaction (CPFP) that pays enough to confirm the
  deposit and your claim together, but the client can always answer with a
  higher-fee conflict. Each round costs both sides more. The provider does
  not do this today; automating it in the future could remove the client's
  incentive to cheat.
- **Your node must see the deposit.** Payment needs the deposit in your Core
  node's mempool. A deposit your node refuses (policy, fee rate, a full
  mempool) is paid only once it confirms.
- **A double-spent swap closes only on proof.** While your Core (with a
  synced `txindex`) does not know the deposit, the provider looks for another
  transaction spending one of the deposit's own inputs, scanning from 144
  blocks below the first claim, 12 blocks per sweep. When that transaction is
  6 blocks deep on the active chain, the swap becomes `LOST`, logs an error,
  and frees its reservation in `max_active_reservations`; the store records
  the conflicting transaction and block. A conflict still in the mempool, a
  deposit merely evicted, or one your node still holds keeps the swap in
  `CLAIMING`. A restart scans again from the same floor. `LOST` is final,
  even if a reorganization deeper than 6 blocks later revives the deposit.

Consider 0 only for small amounts and keep at least 1 for larger ones. An
advertisement carries a single value, so run one maker per policy: for
example, a 0-confirmation maker with a small `terms.amount_bands` and a
1-confirmation maker for larger amounts. Each needs its own store and
identity, but they can share the same Bitcoin Core and LND nodes.

### LND credentials

Use separate scoped macaroons instead of `admin.macaroon`:

```sh
lncli bakemacaroon offchain:read info:read --save_to read.macaroon
lncli bakemacaroon offchain:read offchain:write info:read \
  --save_to payment.macaroon
lncli bakemacaroon invoices:read invoices:write info:read \
  --save_to invoices.macaroon
```

Set `lnd.macaroon` to the read macaroon, `lnd.payment_macaroon` to the payment
macaroon, and `lnd.invoices_macaroon` to the invoices macaroon when the
profile uses hold invoices. Core and LND connections use `127.0.0.1`.

### Relays and Tor

Use relays that accept your announcements (kind 39417), serve gift wraps
(kind 1059) without NIP-42 AUTH, and accept connections from Tor. The Docker
setup defaults to the same relays as the web app, including two onion relays.
Proxied relays must use `wss://`, except v3 onion relays, which may use plain
`ws://` because Tor encrypts and authenticates them. On public Bitcoin
networks, set `relay_proxy` to a loopback Tor `HTTPTunnelPort` such as
`http://127.0.0.1:9080`. Direct connections are refused unless
`allow_direct_relays` is enabled, which exposes your IP address to the
relays. Regtest allows direct connections. Without `relay_proxy`, onion
relays are skipped (one INFO log line) and are not announced.

Failed relay connections log one warning per outage while retries continue
with backoff. Once reconnection and subscription sending succeed, the provider
logs `relay available` at INFO once. Each relay is tracked independently.

Accepted unfinished swaps keep a catch-up filter anchored to their original
firm-offer reservation, so long block waits and provider outages do not move
the history cutoff past a backdated message. Completed and pre-economic
mailboxes keep their bounded rolling history. Cooperative deliveries retry
promptly inside their original deadline; retries never open another signing
window. Relay acceptance is not counterparty acknowledgment.

This delivery improvement needs no schema or configuration migration.
Upgrading reuses existing reservations and pending outbox bytes. Missing
reservation evidence retains the older rolling filter, never an automatic
all-history scan. Restart still abandons unfinished signing attempts, while
already committed contributions remain replayable under existing rules.

Each relay connection attempt runs on its own Tor circuit: the CONNECT
request carries a fresh random `X-Tor-Stream-Isolation` value, which Tor's
default `IsolateSOCKSAuth` treats like a SOCKS user name. Connections to
different relays, and reconnects, never share a circuit, so one slow or
censoring exit cannot cut every relay at once. This needs no torrc change;
only `NoIsolateSOCKSAuth` on the `HTTPTunnelPort` turns it off.

### Notifications

The optional `notifications` section sends operator notifications through
[Apprise](https://github.com/caronc/apprise) (Telegram, ntfy, email, Matrix,
webhooks and many more). The development lock and the Docker image include
it; other installs need the `rill-provider[notifications]` extra, or `serve`
refuses to start.

```json
"notifications": {
  "urls_file": "notify.urls",
  "swap_confirmed": true,
  "summary_time": "08:00"
}
```

`urls_file` is an owner-only (0600) file with one
[Apprise URL](https://github.com/caronc/apprise/wiki/URLBasics) per line;
blank lines and lines starting with `#` are ignored. URLs carry service
tokens, so they never go in the config. Every URL is checked at startup, and
a refused one is reported by line number only.

| Field | Default | Notifies |
| --- | --- | --- |
| `swap_request` | `false` | A client accepted terms (with the amount) |
| `swap_confirmed` | `false` | A swap completed, with its revenue, costs and net |
| `swap_failed` | `false` | A swap failed, was refunded or aborted |
| `swap_lost` | `true` | A swap paid out without getting the funds back |
| `daily_summary` | `true` | Requests, success rate, revenue, costs and net profit |
| `summary_balances` | `true` | Include current balances of configured assets and the Bitcoin Core wallet UTXO count in the daily summary |
| `summary_time` | `"00:00"` | When the daily summary is sent (`HH:MM`, UTC) |
| `low_liquidity` | `true` | Liquidity is below every amount band (not announcing) |
| `relays_down` | `true` | No relay is connected |
| `quotes_paused` | `true` | The chain tip or claim fee estimate is unavailable |
| `service_start_stop` | `false` | Serving started or stopped |
| `alert_after_seconds` | `300` | How long a condition lasts before it is alerted (60 to 86400) |
| `use_tor` | `true` | Send through `relay_proxy` (Tor) when it is set; `false` connects directly |

The three health conditions are alerted once after `alert_after_seconds` and
cleared once on recovery. Events found in the same 15-second poll are combined
into one notification.

The daily summary covers the 24 hours before `summary_time` and is computed
from the store's swap ledger (see
[Persistent state and backups](#persistent-state-and-backups)): accepted
requests and firm offers, swaps closed with their outcomes and success rate,
revenue, mining and routing costs, losses, net profit (in sat, with msat
precision) and EVM gas (in gwei, kept apart). If a closed swap has costs that
were not recorded (not reported by a backend), the summary says so and the
net profit is an upper bound.

By default, the summary also includes current balances (not balances at the
summary window's end): the Bitcoin Core wallet's trusted balance, Lightning
local/remote channel balances, the LND default on-chain account, and every
configured EVM token plus the signer's native gas balance in wei. Remote channel
funds belong to peers; channel balances are not available routing liquidity.
Token amounts use the configured decimals. These are separate snapshots, not
an atomic view or a combined portfolio total.

The Bitcoin Core UTXO count combines `listunspent` (minimum confirmations 0)
with `listlockunspent`, deduplicating outputs. It includes unconfirmed,
unsafe, watch-only and temporarily locked outputs; Core's `listunspent` does
not return immature coinbase outputs. It is not a count of usable funding
inputs. Core reporting needs `getbalances`,
`listunspent` and `listlockunspent` in any `rpcwhitelist`. LND reporting uses
only `lnd.macaroon`: channel balances need `offchain:read`, and the on-chain
balance needs `onchain:read`. Existing credentials are never replaced with a
more privileged macaroon. Missing permissions, timeouts and unavailable
backends show as `unavailable`, not zero; other balances and ledger accounting
are still sent. Reads use a separate, four-thread notification pool with a
bounded wait, never the swap-processing pool. A timeout does not terminate a
running backend call; its source is not read again until that call ends.
Notifier shutdown cancels queued reads without waiting for active ones, but
Python process exit can still wait for active backend calls to finish.

Upgrading an existing config with notifications enabled also enables this
balance reporting to its existing destinations, without changing the config
file or store. Set `"summary_balances": false` to omit both balances and the
UTXO count and skip their RPC reads. With no `notifications` section, nothing
is sent; with `"daily_summary": false`, no balance reads occur.

Notifications are best effort and never affect serving. Nothing about them is
persisted: events that happen while the service is stopped are not sent one
by one, but the next daily summary counts them. Failed deliveries are logged
without the URL.

When `relay_proxy` is set and `use_tor` is on (the default), every
notification goes through Tor and never falls back to a direct connection:
Tor resolves the service name, onion URLs work (for example a Gotify or ntfy
onion service), and HTTPS is still verified against the service's name. Each
connection runs on its own circuit, apart from the relay connections. Only
HTTP services work this way: email, IRC, MQTT, syslog and other plugins that
do not use HTTP are refused (logged as connections outside Tor refused), not
sent around Tor. Services on your LAN cannot be reached through Tor (logged
as unreachable through Tor). For those, or for non-HTTP services, set
`"use_tor": false`; they then see this host's address.
Without `relay_proxy`, notifications connect directly. One INFO line at
startup states which route is used.

Apprise runs in a separate process, which receives the URLs over a pipe and
logs nothing, so no log level shows them. In Tor mode that process refuses
every connection, name lookup, datagram and new process that does not go
through the proxy.

## Persistent state and backups

The store uses schema v21 and opens only a store of exactly that version (see
[Upgrades](#upgrades)).

The store keeps an append-only swap ledger: each firm offer, acceptance and
outcome, and every realized cost (Lightning routing fee, claim, funding and
refund mining fees, EVM gas), written in the same transaction as the swap
event. A cost no backend reported is listed as unrecorded instead of being
counted as zero. A firm offer that grants a rebate (a negative service fee)
also records the rebate, and its completed swap records negative revenue.
Rebates of open offers, and of swaps completed in the last 24 hours, count
against the process's rebate budget; each process derives it from its own
store only.

Reverse spent-output scans retain a block-hash anchor and an immutable replay
floor, checking parent continuity in batches of at most 12 blocks. Above-floor
reorgs durably rewind and resume across restarts. A reorg crossing the floor
pauses automatic refund resolution for operator recovery, which can leave funds
and the held payment pending. Scan backlog also blocks refund-based cancellation.
An already recorded preimage still settles without chain access.

Every funded reverse swap commits its anchor in the same transaction as its
funding. A swap without one is refused for operator recovery: missing metadata
is not permission for a full historical scan, a refund, or a payment retry.

The live store is the authoritative swap state, not a cache. Its database and
owner-lock file belong to one host and one service.

- Keep the store outside any backup or snapshot restore domain.
- Set `authority.outside_restore_domain` and `authority.single_host` to
  `true` only when they describe your deployment.
- Back up the custody key and encrypted provider identity offline.
- Keep the custody key out of store volume images, with owner-only
  permissions and ownership matching the service user.
- Never restore an old store, copy one over the live store, or delete records
  to clear a stuck swap.

Store acquisition checks ownership and provisioned file identity, but it
cannot verify your deployment attestations or detect every storage rollback.

Reverse funding failures release only the complete input set identified by that
build. Persistence refusal requires a same-owner check proving funding remains
ungranted; uncertain commits retain locks. Existing installations' earlier locks
are not swept or inferred from missing metadata. Unknown funding-creation replies
and cancellation after a completed worker may still require operator inspection.

### Upgrades

The Web3 7.16 to 8.0 dependency update adds upstream Python 3.14 support without
changing the store schema or recorded EVM transaction bytes and hashes. Existing
supported stores resume normally; missing, malformed and unsupported stores retain
their existing refusal behavior. This update requires no reprovisioning, migration
or re-signing of pending transactions.

Schema v21 lets the swap ledger record signed revenue and provider rebates. A
v20 store never granted a rebate, so draining it and provisioning a new store
(below) loses no rebate history.

Stop the service before installing a new version. Stores are never upgraded in
place. A store of any other schema version (including v20 and earlier) is
refused with its contents unchanged, with
`live session store version unsupported (found N, requires 21); recreate it with
provision-store`. (If the old process crashed, SQLite may still fold its
committed write-ahead log into the database file; nothing is lost.) An older
release also refuses a newer store.

To move to a release with a new schema, let every in-flight swap finish on the
old release and confirm it with that release's `inspect-swaps` (the new one
cannot open the old store), stop it, keep the old store for your records, and
create a new store with `provision-store` at a new `store_path`. Lightning hold
invoices of unfinished reverse swaps would otherwise stay in LND. The new store
does not know the payment hashes the old one used; LND still refuses to pay an
already paid payment hash or to create a second invoice for an existing one.
The handshake policy is part of the store: changing it also needs a new store.

Handshake features are protocol requirements, not settings. Every session is
epoch-bound (`epoch-bound-session/v1`), and the Bitcoin profiles also require
cooperative claims (`cooperative-claim/v1`). A configuration that still sets
`handshake.features` is refused; delete that key.

## Operations and recovery

After a crash, preserve the store and credentials, and confirm the previous
process has stopped before restarting or running an offline command. Do not
provision a replacement store to work around an error.

### Inspect retained swaps

With the service stopped:

```sh
rill-provider inspect-swaps --config tmp/signet/provider.json --limit 100
rill-provider inspect-swaps --config tmp/signet/provider.json --session-id SESSION_ID
rill-provider inspect-swaps --config tmp/signet/provider.json --after NEXT_AFTER
```

The output is redacted JSON with `action_authority: "none"`. Page with
`next_after`; `--limit` accepts 1 to 1000. Inspection does not contact Core,
LND or relays, and never changes the store's schema.
An empty page does not prove that no external payment exists.

### Reconcile an ambiguous payment

For a retained `PAYING` swap, stop the service and run:

```sh
rill-provider reconcile-payment --config tmp/signet/provider.json \
  --session-id SESSION_ID
```

This queries LND with the read macaroon and never sends a payment. A verified
matching preimage moves the swap to `PAID`, and normal settlement resumes
after restart. `UNKNOWN`, `IN_FLIGHT` and backend-reported `FAILED` leave the
swap `PAYING`. Missing records and RPC errors are not permission to retry;
preserve the original node and store state while investigating.

## Safety limits

- The provider never recreates missing stores, repairs unknown state, replays
  consumed payment dispatches, or treats missing metadata as payment failure.
- Ambiguous payments can stay unresolved and keep their reserved capacity.
  Offline reconciliation does not authorize a retry, refund or capacity
  release.
- Cooperative Bitcoin claims are optional for safety: if the peer is
  unavailable, script-path claim or refund recovery remains.

## Tests

From `rill-provider/`, the default CI selection:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  -m 'not native_crypto and not bitcoin_core and not lnd and not web_nip59_interop' \
  --basetemp=tmp/pytest-ci
```

Opt-in diagnostics use test infrastructure, never your live credentials:

| Marker | Enable with | Needs |
| --- | --- | --- |
| `native_crypto` | `RILLSWAP_RUN_NATIVE_CRYPTO=1` | Built native library at `RILL_CRYPTO_LIBRARY` |
| `bitcoin_core` | `RILLSWAP_RUN_BITCOIN_CORE=1` | Docker for pinned Bitcoin Core regtest fixtures |
| `lnd` | `RILLSWAP_RUN_LND=1` | Python 3.14 and Docker with pinned linux/amd64 Core, LND and Python images |
| `lnd` (merchant tests) | `RILLSWAP_RUN_LND=1 RILLSWAP_RUN_BUN_MERCHANT=1` | Bun 1.3.11 and installed `rill-payments` dependencies, plus the LND prerequisites |
| `web_nip59_interop` | `RILLSWAP_RUN_WEB_NIP59=1` | `RILL_CRYPTO_LIBRARY`, Bun and installed `rill-web` dependencies |
| `anvil` | `RILLSWAP_RUN_ANVIL=1` | Local Anvil with chain ID 31337 (`RILLSWAP_ANVIL_RPC` overrides `http://127.0.0.1:8545`) |

Select one with `-m <marker>`. See the test source for exact fixture
requirements. After an interrupted Docker diagnostic, check container
ownership and test-run labels before removing leftovers.

## Further reading

- [Protocol specifications](../rill-docs/specs/)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Development and the disposable stack](../DEVELOPMENT.md)
- [Security policy](../SECURITY.md)
