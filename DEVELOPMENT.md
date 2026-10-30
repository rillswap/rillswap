# Development environment

A complete local regtest stack: Bitcoin Core, three LND nodes, a Nostr relay,
an auto-miner, a maker (liquidity provider) for each of the four swap
profiles, a user toolbox with the `rill` CLI, the browser swap page, a local
Anvil EVM chain with two fake stablecoins (fUSDC, fUSDT) and a gas sponsor, a
private Monero regtest chain, and a demo shop backed by the rill-payments
merchant services. Everything runs in Docker Compose and is driven by one
script, `dev/devctl`.

All data is disposable regtest data with fixed, public credentials. Never
point any of it at real funds.

## Requirements

- Docker with Compose v2 (rootless works).
- Network access for the first image build (Debian packages, PyPI, Bun
  packages, the checksum-pinned secp256k1 release on GitHub, the
  checksum-pinned Monero CLI release from getmonero.org).
- Optional: Chromium/Firefox for the browser swap page.

## Quick start

```sh
dev/devctl up        # build the image, start everything, wait for bootstrap
dev/devctl info      # maker keys, relay URL, height, balances
dev/devctl smoke     # both swap directions and a shop purchase per payment method
```

The first `up` takes a few minutes (image build). Later runs reuse the image and
all chain/wallet/maker state. `dev/devctl help` lists every command.

## Full-stack CI acceptance

`.github/workflows/compose-e2e.yml` runs on pushes, pull requests and manual
dispatches. It builds and starts **every** service in `dev/compose.yaml` with
the `dev/compose.ci.yaml` overlay (same applications, no development file
watchers) and fresh, run-specific volumes, checks service health, real chain
identities, funded Lightning channels, all shop rails and all four maker announcements,
then runs the CLI smoke suite and Chromium against the production web bundle.

The browser suite covers all four swap profiles, both external-wallet and
configured-node Lightning payment, actual Bitcoin claim broadcast and
settlement, wallet and gas-sponsored ERC20 claims, encrypted recovery/reload,
and storefront purchases over Lightning, Bitcoin swaps, fUSDC, fUSDT and
single/split Monero payments. It checks confirmed payouts, settled invoices,
provider terminal states, verified receipts and receipt persistence across
application restarts. Component/schema/vector/artifact checks still run
separately; these tests do not replace them.

Concurrent acceptance tests overlap two swaps per profile, including shared
Core-wallet CLI funding and shared EVM-account browser funding. They also
check independent recovery records and coin reservations across wallet reloads.

Storefront Lightning order creation briefly stops only the isolated auto-miner,
drains mining RPCs and waits for LND to match Core's tip. Mining resumes before
payment, including on checkout failure. This controls fixture timing without
relaxing the merchant's freshness checks or retrying checkout creation.

The component CI's actual-HTTPS merchant diagnostic uses pinned Chrome for
Testing 157.0.8090.0. Playwright 1.63's bundled Chromium reports
fully consumed streaming responses as aborted because of
[an upstream EOF bug](https://chromium.googlesource.com/chromium/src/+/62473ad0f747e245e514c93e741bb8e168a2a207).
Only this diagnostic uses the fixed development snapshot; other browser tests
keep Playwright's bundled browser. The SDK's streaming byte limit, TLS checks
and no-aborted-request assertions remain unchanged. To reproduce on Linux x64:

```sh
cd rill-payments
browser=$(sh scripts/install-merchant-chromium.sh)
RILLSWAP_RUN_MERCHANT_BROWSER=1 RILLSWAP_MERCHANT_BROWSER_EXECUTABLE="$browser" \
  bun test tests/regtestMerchantHttpsDiagnostic.test.ts -t 'default browser reads actual merchant HTTPS'
```

Forward Bitcoin browser tests fund swaps both with a finalized PSBT and with
a plain wallet send that the page discovers through the local chain API.

No chain, relay, provider or merchant transport is mocked. The injected EVM
wallet forwards requests to Anvil's unlocked disposable account, rather than
testing a wallet extension. The gas sponsor is the existing dev-only stand-in,
executing real EntryPoint/delegate/HTLC contracts, not a production bundler.

To reproduce locally without touching an existing dev stack:

```sh
export COMPOSE_PROJECT_NAME=rill-reverse-browser-local-$(date +%s)
export COMPOSE_FILE=dev/compose.yaml:dev/compose.ci.yaml
export RILLSWAP_RUN_COMPOSE_E2E=1
export RILL_DEV_WEB_PORT=15273 RILL_DEV_SHOP_PORT=18090 RILL_DEV_RELAY_PORT=17777
export RILL_DEV_CHAIN_PORT=18091 RILL_DEV_BROADCAST_PORT=18092 RILL_DEV_NODE_PORT=18093
export RILL_DEV_SPONSOR_PORT=18094 RILL_DEV_ANVIL_PORT=18545
(cd rill-payments && bun install --frozen-lockfile --ignore-scripts)
(cd rill-web && bun install --frozen-lockfile --ignore-scripts && bunx playwright install --with-deps chromium)
docker compose up -d --build
dev/devctl info
(cd rill-web && bun run test:e2e -- stack.spec.ts)
dev/devctl smoke
(cd rill-web && bun run test:e2e -- --grep-invert 'whole Compose stack')
# Only delete the fresh project's disposable regtest data:
docker compose down --volumes --remove-orphans
```

Keep the exported project/ports for every command. Use unused ports and a new
project name for each run. Tests refuse the default project and browser port.

For real relay-failure acceptance, append `dev/compose.relay-resilience.yaml`
to `COMPOSE_FILE`, set an unused `RILL_DEV_RELAY_ALT_PORT`, and set
`RILLSWAP_RUN_RELAY_RESILIENCE=1`. The overlay provisions two independent relays
and matching provider/browser endpoints only for fresh test configurations.
The Bitcoin browser tests disconnect a relay that actually carried session
messages while mining is paused, then verify settlement over the remaining
path. Never run these fault tests against a development project you need to keep.
CI always saves service status/logs and failure traces/screenshots before
removing its own containers and volumes. Diagnostics contain disposable dev
data only, never use this stack with real funds or credentials.

## Default development endpoints

| What | Where |
| --- | --- |
| Browser swap page | http://127.0.0.1:5273/swap.html |
| Demo shop | http://127.0.0.1:8090/ |
| Anvil JSON-RPC (chain id 31337) | http://127.0.0.1:8545 |
| Nostr relay (from the host/browser) | ws://127.0.0.1:7777 |
| Nostr relay (inside the stack) | ws://relay:8080 |
| Read-only regtest chain API | http://127.0.0.1:8091/api |
| Explicit regtest transaction broadcast | http://127.0.0.1:8092/api/tx |
| Explicit user-node browser transport | http://127.0.0.1:8093 |
| Gas sponsor (ERC-4337 bundler stand-in) | http://127.0.0.1:8094 |

Override host ports with `RILL_DEV_WEB_PORT`, `RILL_DEV_SHOP_PORT`,
`RILL_DEV_RELAY_PORT`, `RILL_DEV_CHAIN_PORT`, `RILL_DEV_ANVIL_PORT`,
`RILL_DEV_BROADCAST_PORT`, `RILL_DEV_NODE_PORT` and `RILL_DEV_SPONSOR_PORT`, the Bitcoin auto-miner
interval with `RILL_DEV_BLOCK_SECONDS` (default 10, `0` disables), and the
Anvil block interval with `RILL_DEV_ANVIL_BLOCK_SECONDS` (default 2), and the
Monero block interval with `RILL_DEV_MONERO_BLOCK_SECONDS` (default 2), for
example `RILL_DEV_WEB_PORT=9273 RILL_DEV_CHAIN_PORT=9091 dev/devctl up`.

## What runs

| Service | Role |
| --- | --- |
| `bitcoind` | Bitcoin Core v30 regtest, `txindex=1`. Wallets: `miner`, `user`, `maker`. |
| `lnd-maker`, `lnd-user`, `lnd-merchant` | LND nodes. 5,000,000 sat channels: maker to user, user to maker, maker to merchant. |
| `relay` | `nostr-rs-relay`, the only channel between makers and users. |
| `bootstrap` | One-shot, idempotent setup (below). Reruns on every `up`. |
| `miner` | Mines one Bitcoin block every `RILL_DEV_BLOCK_SECONDS` and one Monero block (to the buyer) every `RILL_DEV_MONERO_BLOCK_SECONDS`. |
| `maker-btc-to-ln` | `rill-provider serve`: takes on-chain BTC, pays the user's Lightning invoice. |
| `maker-ln-to-btc` | `rill-provider serve`: takes a Lightning hold payment, pays on-chain BTC. |
| `maker-erc20-to-ln`, `maker-ln-to-erc20` | `rill-provider serve` for the RS-010 stablecoin profiles on Anvil (ERC20Swap v6 HTLC, fUSDC at a fixed 100,000 fUSDC/BTC). The maker's HTLC signer is Anvil account 3. |
| `tools` | User toolbox. `devctl swap`, `devctl rill`, `devctl shell` run here. |
| `web` | Builds `rill-web` (rebuilding on change) and serves `dist/`. |
| `chain`, `broadcast` | Read-only Esplora-style chain API and explicit transaction broadcast for the browser (see [Browser adapters](#browser-adapters)). |
| `user-node` | Scoped browser transport to `lnd-user` for paying from a configured node. |
| `gas-sponsor` | Local ERC-4337 bundler/paymaster stand-in for gas-sponsored stablecoin claims. |
| `merchant` | `rill-payments` merchant API (`bun src/cli.ts serve`) on `lnd-merchant`. |
| `anvil` | Foundry Anvil 1.8.4, chain id 31337, standard test mnemonic, state kept across restarts. |
| `monerod` | Monero v0.18.5.3 regtest (`fakechain`): private, fixed difficulty, no peers, chain kept across restarts (`--keep-fakechain`). |
| `monero-wallet-merchant`, `monero-wallet-buyer` | One `monero-wallet-rpc` each (wallets `merchant`, `buyer`, no password). Reachable only inside the stack. |
| `shop` | Demo storefront ([`rill-payments/examples/demo-shop`](rill-payments/examples/demo-shop)), plus the fUSDC/fUSDT and Monero receipt services. |

`bootstrap` checks before acting at every step, so it is safe to rerun and it
completes an interrupted attempt. It creates the wallets, mines to 150 blocks,
funds the `maker` and `user` LND nodes and Core wallets (10 BTC each), opens
the channels, provisions one maker identity, custody key, config and store per
direction, deploys the ERC20Swap v6 HTLC and the fUSDC dev token on Anvil
once (one million fUSDC each to the user, Anvil account 1, and the maker
signer) and provisions the two stablecoin makers, writes the user's age key, and prepares the merchant's keys, admin
token, scoped invoice macaroon and config (the merchant provisions its own
ledger on first start), and creates the two Monero wallets and mines the
Monero chain to 130 blocks to the buyer (100 coinbase outputs: spendable
funds and enough ring decoys). Results land in the `state` volume:

```
/state/info.json                 maker keys, relay URLs, LND pubkeys
/state/makers/<direction>/       provider.json, identity, custody key, store
/state/evm/contracts.json        Anvil HTLC and fUSDC addresses, maker/user accounts
/state/user/                     age.key, network.json, Core/LND credentials
/state/user/swaps/<time>-<dir>-<unique>/  recovery files from `devctl swap`
/state/merchant/                 merchant config, keys, admin token, ledger
/state/shop/orders.json          demo shop orders
/state/shop/native/              stablecoin keys; per token config.json, ledger
/state/shop/monero/              Monero rail keys, config.json, ledger
```

The shop sets up the stablecoins itself on first start: it deploys
`DevStablecoin` twice from Anvil account 0, mints one million of each to the
buyer (account 1), records each token in `/state/shop/native/<token>/config.json`
and provisions its receipt ledger. Shop revenue goes to account 2. If the Anvil
chain no longer matches those records, the shop logs it and disables the token
rails rather than redeploying: `dev/devctl reset`.

The Monero rail works the same way: on first start (empty
`/state/shop/monero/`) the shop records the merchant wallet's primary address
and the chain's block-1 hash in `config.json` and provisions its ledger. Any
partial state, another wallet, or a reset chain disables the rail; nothing is
recreated over existing state. Regtest addresses look exactly like mainnet
ones, so the rail also refuses any daemon that does not report `fakechain`.

Rill clients only accept Core and LND on numeric loopback, so each Rill
container forwards `127.0.0.1:18443` to `bitcoind` and `127.0.0.1:10009` to its
LND node (`dev/entrypoint.sh`). Core authentication uses a static `__cookie__`
rpcauth entry, so the cookie file stays valid across restarts.

## Watching a maker

```sh
dev/devctl logs maker-btc-to-ln          # live log (filter: | grep -v httpx)
dev/devctl logs relay                    # announcements (kind 39417), gift wraps (1059)
dev/devctl maker-swaps btc-to-ln         # the maker's swap records
dev/devctl balances                      # Core wallets and LND channel balances
```

A maker publishes a signed announcement on the relay, then waits for
handshakes. One "announcement not accepted by any relay; will retry" warning at
startup is expected while its relay connection opens. Each maker's earnings
land in the Core `maker` wallet (BTC to LN claims) or in LND channel balance
(LN to BTC).

`maker-swaps` stops that maker for a few seconds, because `inspect-swaps` takes
the store's owner lock. It supports `btc-to-ln` stores; for an `ln-to-btc`
store with swaps it fails with "swap inspection state unsupported".

To change maker terms (fees, amount bands), edit
`/state/makers/<direction>/provider.json` in `devctl shell` and restart the
maker, or `dev/devctl reset` to start over. Bootstrap never overwrites an
existing config.

## Swapping as a user (CLI)

```sh
dev/devctl swap btc-to-ln 50000     # pay a fresh 50,000 sat user invoice with on-chain BTC
dev/devctl swap ln-to-btc 50000     # pay Lightning, receive 50,000 sat on chain
```

The helper creates the invoice (`btc-to-ln`), runs `rill swap` in the `tools`
container with the right maker key, credentials and a fresh recovery path,
and prints the `rill` output. Extra flags pass through, for example
`dev/devctl swap btc-to-ln 50000 --fee-rate 5`. The exact command is printed,
so you can rerun or vary it with `dev/devctl rill ...` or inside
`dev/devctl shell`.

Separate invocations can run simultaneously. Each has its own session and
private recovery directory, including invocations started in the same second.
Existing recovery directories are unchanged.

## Swapping as a user (browser)

Open http://127.0.0.1:5273/swap.html (use 127.0.0.1, not `localhost`: the
page's CSP allows loopback relays, and another local server may own
`localhost` on IPv6). The local build defaults to regtest, the local relay,
chain API and gas sponsor, and a recovery wallet derived and stored in the
browser. Pick the pair with **You send / You receive**.

- **BTC to Lightning:** `dev/devctl web-inputs 50000` prints a fresh user
  invoice. Paste it, accept a quote, then run
  `dev/devctl send-btc <address> <btc>` with the exact deposit address and BTC
  amount shown. This signs and broadcasts immediately from the user wallet,
  paying the transaction fee separately. It prints the transaction ID.
  The browser discovers the deposit and proceeds after confirmation.
  **Advanced** still supports `fund-psbt` and explicit raw transaction broadcast.
- **Lightning to BTC:** compare offers, approve one, then pay the hold invoice
  with `dev/devctl pay <bolt11>`. The page claims the on-chain output.
- **USDC/USDT to Lightning:** needs an injected EVM wallet (for example
  MetaMask) on the Anvil network (RPC http://127.0.0.1:8545, chain id 31337)
  with Anvil account 1 imported; it holds one million fUSDC. The wallet signs
  the approval and the HTLC lock.
- **Lightning to USDC/USDT:** type a receiving address, pay the hold invoice
  with `dev/devctl pay <bolt11>`; the local gas sponsor submits the claim, so
  the address needs no ETH.

Recovery files are encrypted to the browser-derived age identity. The
recovery panel can inspect them and prepare explicitly approved refunds. To
recover with the CLI instead, download `rillswap-recovery.age-key` from the
recovery details.

The local explorer shows transaction inputs, exact output amounts, and active
chain confirmation status at `http://127.0.0.1:8091/tx/<txid>`. Use **Refresh
status** to update it. It does not estimate transaction fees.

Address discovery reads the full active regtest history and mempool only when
requested, without a wallet import, index, or startup scan. Queries have a
12-second scan budget, a one-million-block cap, and bounded results. Timeouts,
reorganizations, and oversized histories return unavailable rather than partial
or empty history. For an oversized disposable history, start fresh with
`dev/devctl reset` (this deletes the development stack's data).

Existing volumes need no migration. If your volumes predate address
discovery, recreate the Core and reader containers so Core grants the
read-only activity RPC:

```sh
docker compose -f dev/compose.yaml up -d --force-recreate bitcoind chain
```

An older Core container without that permission returns unavailable for address
queries. Existing volumes are retained by the recreation command.

The merchant CLI configuration requires an explicit `network`. If an older
development volume has `/state/merchant/config.json` without it, add
`"network": "regtest"` to that file before restarting the merchant. Missing
network configuration is refused; existing merchant ledgers are not migrated.

## Paying in the demo shop

Open http://127.0.0.1:8090/, pick a product, pick a payment method and place
the order. Prices are in USD at a fixed demo rate (1 BTC = 100,000 USD). The
shop backend creates the merchant intent and invoice with its admin token; the
browser only talks to the shop. The order page polls its status and, once the
merchant accepts the payment, verifies the merchant's signed acceptance
against the Ed25519 key the shop pinned from the merchant's event key.

- **Lightning:** `dev/devctl pay <invoice>` pays from `lnd-user`, routed
  user to maker to merchant.
- **Bitcoin on-chain:** `dev/devctl swap btc-to-ln <invoice>` funds a swap
  from the Core `user` wallet and the BTC to LN maker pays the shop's invoice.
  The browser swap page works too: paste the shop invoice instead of the one
  from `web-inputs`.
- **fUSDC / fUSDT:** `dev/devctl pay-token <order-id>` (1 token = 1 USD). This
  uses the rill-payments native sandbox receipt rail: the buyer signs an
  EIP-712 binding for the order and its next nonce, the merchant reserves it,
  the buyer sends exactly that ERC20 `transfer`, and after 6 confirmations
  (about 12 s) the merchant records a signed receipt that the shop verifies.
  A plain wallet transfer without the binding is never accepted, so MetaMask
  alone cannot pay; it can still watch balances on `http://127.0.0.1:8545`.
- **Monero:** `dev/devctl pay-xmr <order-id>` (1 XMR = 200 USD) sends the
  exact amount from the buyer wallet to the order's own subaddress;
  `--parts 2` splits it over two transactions. This uses the rill-payments
  Monero regtest receipt rail: the shop polls the merchant wallet every 3 s and
  counts confirmed incoming transfers to that subaddress (10 confirmations,
  about 20 s). Exactly the price, in blocks between order creation and expiry,
  is paid and gets a signed receipt. More than the price (even dust), any
  transfer timestamped outside that window, or an incomplete sum after expiry
  goes to reconciliation. A payment that later leaves the chain (reorg) marks
  the order's evidence impaired; the acceptance is kept.

`dev/devctl shop-smoke` buys once over Lightning and once via a swap, and
`dev/devctl token-smoke` once with each token, and `dev/devctl xmr-smoke` with
Monero (one payment, then one split in two); all check the signed acceptance. The merchant API itself is reachable only inside the stack
(`merchant:8788`, forwarded to the CLI's loopback listener), so
`dev/devctl shell` plus `curl` with the token in `/state/merchant/admin.token`
is the way to call it by hand.

## Mining, timeouts and refunds

```sh
dev/devctl miner pause      # freeze both chains (Bitcoin and Monero)
dev/devctl mine 300         # jump past a refund height
dev/devctl miner resume
```

At the default 10 s block interval, the BTC to LN refund delay (288 blocks) is
about 48 minutes. To exercise refunds, pause the relevant maker
(`docker compose -f dev/compose.yaml stop maker-btc-to-ln`) after funding,
mine past the refund height, and follow the recovery steps in
[`rill-cli/README.md`](rill-cli/README.md) inside `dev/devctl shell`. The
stack-specific values are: network `/state/user/network.json`, crypto library
`$RILL_CRYPTO_LIBRARY`, identity `/state/user/age.key`, cookie
`/state/user/core.cookie`, RPC port 18443, and LND port 10009 with
`/state/user/tls.cert` and `/state/user/admin.macaroon`.

## Raw access

```sh
dev/devctl bitcoin-cli -rpcwallet=user getbalances
dev/devctl lncli maker listchannels
dev/devctl lncli merchant listinvoices
dev/devctl lncli user addinvoice --amt 1000
dev/devctl invoice 1000 --node maker
dev/devctl pay <bolt11>
dev/devctl cast block-number                           # Foundry cast on Anvil
dev/devctl cast call <token> "balanceOf(address)(uint256)" <address>
dev/devctl cast send <token> "mint(address,uint256)" <address> 1000000000 \
    --private-key <anvil key>                           # fake-token faucet
dev/devctl shell                       # bash with rill, rill-provider, devtool
docker compose -f dev/compose.yaml exec monero-wallet-buyer \
    curl -s -d '{"jsonrpc":"2.0","id":0,"method":"get_balance"}' http://127.0.0.1:18082/json_rpc
```

`dev/devctl balances` includes both Monero wallets. Monero RPC is never
published to the host: use `docker compose exec` as above (daemon on
`monerod:18081`, wallets on port 18082).

## Changing code

The repository is mounted read-only at `/src`, and the Python packages are
installed editable from it. After editing:

- provider code: `dev/devctl restart maker-btc-to-ln maker-ln-to-btc maker-erc20-to-ln maker-ln-to-erc20`
- CLI code: nothing (each `rill` run starts fresh)
- `rill-web/src`, `swap.html`, `index.html`: the `web` service rebuilds; reload
  the page
- `rill-payments/examples/demo-shop`: the shop restarts itself (`bun --watch`);
  after editing `DevStablecoin.sol`, run
  `bun examples/demo-shop/generate-stablecoin.ts` in `rill-payments` and
  reset the stack (deployed tokens are pinned by runtime code hash)
- `rill-payments/src`: `dev/devctl restart merchant shop`
- `dev/devtool.py`: nothing for commands; `dev/devctl up` reruns bootstrap
- dependencies, native crypto, `dev/entrypoint.sh`, `dev/Dockerfile`, or
  `rill-payments` code the web page imports: `dev/devctl build && dev/devctl up`

The shared dev image is built once, by `chain`. Targeted starts also include
that stateless reader through service dependencies. `dev/devctl build tools`
rebuilds the shared image and buildable dependencies, including the Monero
image. With direct `docker compose build` commands, pass `--with-dependencies`
to include the selected service's image builder.

## Stopping and resetting

```sh
dev/devctl down     # stop; keeps chain, wallets, channels and maker stores
dev/devctl reset    # delete every volume (asks first); next `up` starts fresh
```

Volumes belong to the `rillswap-dev` Compose project: `bitcoind`, `lnd-maker`,
`lnd-user`, `lnd-merchant`, `anvil`, `monerod`, `monero-merchant`,
`monero-buyer`, `relay`, `state`. Reset them together. A partial reset (for
example only `bitcoind`) leaves channels and stores pointing at a chain that no
longer exists.

## Browser adapters

These regtest-only services let the browser reach the local chain and node
without holding node credentials:

- `chain`: read-only Esplora-compatible routes for blocks, tip, transactions
  and confirmed unspent outputs. Missing or inconsistent samples are reported
  as unavailable, never as unspent, and the browser checks the raw bytes
  itself.
- `broadcast`: accepts signed transaction hex at `POST /api/tx`, checks the
  regtest genesis, preflights and sends once. An uncertain result is never
  retried.
- `user-node`: forwards explicit browser payment actions to the fixed user
  LND node over verified TLS with a URI-restricted macaroon. The browser owns
  route selection, approval and limits. It is used when you pay a Lightning
  to BTC swap from a configured node under **Advanced**.

Origin and Host checks are local safeguards, not production authentication;
the macaroon can make arbitrary routed regtest payments. No recovery secrets
are uploaded, and credentials stay in browser memory. The adapters never
repair state, reset wallets, scan, replay transactions or pay at startup;
address-history scans run only on explicit requests.

Apply adapter changes without resetting volumes:

```sh
docker compose -f dev/compose.yaml up -d --build bitcoind chain broadcast user-node web
```

On an existing stack, provision only the browser node capability:

```sh
docker compose -f dev/compose.yaml run --rm --no-deps bootstrap python -c \
  'import sys; sys.path.insert(0,"/src/dev"); from devtool import provision_browser_node; provision_browser_node()'
docker compose -f dev/compose.yaml up -d --no-deps user-node
```

A partial provisioning is kept and blocks replacement. Port overrides:
`RILL_DEV_BROADCAST_PORT` (8092) and `RILL_DEV_NODE_PORT` (8093). Opt-in
checks: `RILLSWAP_TEST_CHAIN_AUTH=1 pytest dev/tests/test_chain_core_auth.py`
(isolated disposable node) and
`RILLSWAP_TEST_USER_NODE=1 pytest -q dev/tests/test_user_node_live.py`
(never dispatches a payment).

## Tests

`dev/tests/` checks the stack's static invariants (rpcauth hashes match the
credentials devtool and the cookie use, the Monero chain persists and its RPC
stays private). Run it with any Python that has
`httpx` and `pytest`, for example `rill-cli/.venv/bin/python -m pytest dev/tests`.
`dev/devctl smoke` is the end-to-end check.

[`rill-docs/ATTACKS.md`](rill-docs/ATTACKS.md) lists the known Lightning and
atomic-swap attacks with a reference, RillSwap's status and the test for each.
Keep it current when a defense or a pinned dependency changes.

## Troubleshooting

- **Image build hangs at `apt-get update`:** containers cannot resolve DNS.
  With rootless Docker, the host's ISP resolvers may not answer from
  containers. Set `"dns": ["1.1.1.1", "9.9.9.9"]` in
  `~/.config/docker/daemon.json` (rootless) or `/etc/docker/daemon.json`, then
  restart Docker.
- **Port already in use:** set the matching `RILL_DEV_*_PORT` variable.
- **A maker exits at start:** `dev/devctl logs maker-<direction>`. If its store
  or config is broken, `dev/devctl reset`.
- **Bootstrap fails:** `dev/devctl logs bootstrap`, fix, then `dev/devctl up`
  again. It resumes where it stopped.
- **A token order stays `waiting` after an Anvil restart:** Anvil keeps blocks
  but not historical state across restarts, so a payment that was in flight
  during the restart cannot be verified. Place a new order.
- **Monero is unavailable with "order history is unreadable":** the shop
  could not parse `/state/shop/orders.json` and moved it to
  `orders.json.unreadable-<time>`. While that file exists the shop will not set
  up Monero state (it cannot tell whether Monero orders existed). Inspect it
  with `dev/devctl shell`, then delete it or `dev/devctl reset`.
- **Bootstrap says a Monero wallet does not match the chain:** the `monerod`
  volume was deleted while wallets or shop state remained. `dev/devctl reset`.
- **Anvil account keys:** the standard test mnemonic
  (`test test ... junk`), for example
  `dev/devctl cast wallet private-key --mnemonic "test test test test test test test test test test test junk" --mnemonic-index 1`.
