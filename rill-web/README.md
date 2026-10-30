# rill-web

The RillSwap browser app swaps Bitcoin to or from Lightning, and USDC/USDT to
or from Lightning. It is a static site with no backend of its own: it
discovers providers over Nostr, validates contracts, transactions and
signatures locally, and keeps encrypted recovery records in the browser.

Supports mainnet, signet, testnet4, and regtest.

Run simultaneous swaps in separate tabs, one active workflow per tab. Tabs
share the recovery wallet but keep sessions, funding and recovery records
separate. Providers can service multiple in-flight swaps.

Token funding from the same account coordinates approval and lock confirmation
across tabs using Web Locks. Other swaps can settle while a tab waits for its
turn. Browsers without Web Locks cannot start token funding. SDK hosts sharing
an EVM account must provide `Erc20SwapHooks.withFundingLock` to serialize that
same funding span by chain, account, token and HTLC address. This coordination
is origin-local, not a lock against other sites or wallet applications.

<table>
  <tr>
    <td width="33%"><img src="../rill-docs/images/swap-quote.png" alt="Quote for a Bitcoin to Lightning swap"></td>
    <td width="33%"><img src="../rill-docs/images/swap-funding.png" alt="Deposit address and QR code for funding the swap"></td>
    <td width="33%"><img src="../rill-docs/images/swap-paid.png" alt="Paid invoice with the preimage as proof of payment"></td>
  </tr>
  <tr>
    <td align="center">Paste an invoice and get a verified quote</td>
    <td align="center">Fund the Taproot contract from any wallet</td>
    <td align="center">The provider pays; the preimage proves it</td>
  </tr>
</table>

`swap.html` is the swap app and `index.html` a disconnected diagnostic
preview. In the GitHub Pages build, the swap app is the landing page and the
preview is `diagnostic.html`.

## Install

Use Bun 1.3.11, matching CI. This component depends on `rill-payments` from
the same checkout.

```sh
cd rill-web
bun install --frozen-lockfile
```

## Quick start

Run the full Docker development stack from the repository root:

```sh
dev/devctl up
```

Open http://127.0.0.1:5273/swap.html (the demo shop is at
http://127.0.0.1:8090/). See [DEVELOPMENT.md](../DEVELOPMENT.md) for
walkthroughs.

For standalone development, from `rill-web/`:

```sh
VITE_RILLSWAP_NETWORK=signet bunx vite --host 127.0.0.1
```

Open `/swap.html` and pick a test network in Settings. The page loads
provider listings from the configured relays when it opens, when you
switch networks, and again every five minutes while the tab is visible and
no swap is running; expired offers leave the list as soon as they expire.
Nothing else connects until you start a swap.

Starting a new swap checks this page for a changed application bundle. If a newer
bundle is published, reload when prompted; no payment has been started. Unavailable
checks proceed normally, and documentation-only changes do not prompt. This check
does not interrupt existing swaps or recovery, and cannot detect deployments after
submission or CDN caches still serving the old page. The crypto WASM still loads
when needed; if it becomes unavailable, cooperation falls back to script-path claims.
Tabs opened before this safeguard was deployed need a manual reload to gain it.

## Configuration

Deployment defaults are set and validated at build time.

Connection edits (Nostr relays, mempool API, broadcast API and EVM RPC) are saved
in this browser when a valid edit leaves its field. Profiles are separate for
each deployment directory and complete Bitcoin network identity, including the
regtest namespace. Directory, `index.html` and `swap.html` aliases share a profile;
sibling deployments do not. Network selection and all other settings remain
transient. A changed complete network identity selects a separate profile, without
migrating or deleting the old one. Other tabs do not apply edits live.

Only explicit overrides are stored. Untouched fields follow new defaults after
an application update; custom values remain unchanged. A custom relay list is
never merged with new default relays. Editing a field back to its current default
removes its override. **Reset connection settings to defaults** restores current
defaults for the selected profile only, without touching recovery keys, history
or other profiles. Existing installations start with current defaults, with no
preference migration or writes on load.

Unreadable or unsupported saved settings are preserved and require an explicit
reset before fallback connections are used. If browser storage is blocked, reset
explicitly permits current defaults for this session; edits remain session-only
and a warning explains that old saved settings may return after reload. Endpoint
validation, CSP and CORS restrictions still apply. Preferences never initiate
payments, signing or broadcasting.

The swap footer shows the first seven characters of the build's Git commit,
linked to that commit on GitHub. Builds read the local checkout's `HEAD`;
source archives or containers without Git can set `RILLSWAP_BUILD_COMMIT` to
the full commit hash. If no valid revision is available, the link is omitted.
This identifies the base commit, not uncommitted changes. Revision-only changes
do not trigger the application bundle update warning.

| Variable | Meaning |
| --- | --- |
| `VITE_RILLSWAP_NETWORK` | `mainnet`, `signet`, `testnet4` or `regtest` |
| `VITE_RILLSWAP_RELAYS` | Nostr relay URLs, comma or whitespace separated |
| `VITE_RILLSWAP_MEMPOOL_API` | Esplora-compatible chain API |
| `VITE_RILLSWAP_BROADCAST_API` | Transaction broadcast API |
| `VITE_RILLSWAP_NODE_API` | Optional user-node browser transport |
| `VITE_RILLSWAP_EVM_RPC` | Read-only EVM RPC endpoint |
| `VITE_RILLSWAP_EVM_ASSETS` | JSON map from `USDC`/`USDT` to trusted, complete RS-010 asset identities |
| `VITE_RILLSWAP_EVM_SPONSOR` | Gas sponsor endpoint |
| `VITE_RILLSWAP_EVM_ENTRY_POINT` | Pinned ERC-4337 EntryPoint address |
| `VITE_RILLSWAP_EVM_7702_DELEGATE` | Pinned EIP-7702 delegate address |
| `VITE_RILLSWAP_EVM_SPONSOR_POLICY` | Optional sponsor gas policy UUID |
| `VITE_RILLSWAP_DEPLOYMENTS` | JSON map from network name to a sibling build's relative directory (`"../"`, `"./signet/"`); the header network picker opens these instead of switching in place |

Set the sponsor endpoint, EntryPoint and delegate together, or none of them.
A build without configuration opens mainnet with swaps enabled. The older
single-relay `VITE_RILLSWAP_RELAY` still works but cannot be combined with
`VITE_RILLSWAP_RELAYS`. Up to eight relays are allowed. Plaintext `ws://` relays
are only allowed on loopback for regtest and for v3 onion relays, which Tor
encrypts and authenticates end to end.

Without configuration, mainnet, signet and testnet4 use six public relays
that serve RillSwap's gift-wrapped messages without NIP-42 AUTH, keep provider
announcements, and accept Tor exits, plus two onion relays. The onion relays
are opportunistic: they only connect in a browser that reaches onion services
(Tor Browser), and a failure to reach them is not reported. The Content
Security Policy admits `wss:` and `ws://*.onion` relays and any `https:` origin, so users can
point Settings at their own mempool or Esplora instance (transaction links
use the same instance). Plain `http:` is admitted only for the loopback
endpoints configured at build time. Custom endpoints must allow CORS.

Live swaps retain their session across relay disconnects and restore the
original mailbox history filter, even after long confirmation waits. Up to
two permitted relay paths may be active. Alternatives must be in the user's
selected relay set and the provider's signed endpoints; merely caching an
announcement does not make a relay a provider endpoint. Extra paths expose
messaging metadata to those relays. Recovery archive queries remain separate
and read-only. Cooperative request retries reuse the original signed message
and nonce within the original single 30-second window, never a new attempt.

New stablecoin swaps require independently configured asset pins. Each entry
includes the chain, HTLC and token addresses, decimals, block interval and
deployment namespace from RS-010. Provider symbols never select a token.
Pins apply only to the configured Bitcoin network; local Anvil pins must match
its regtest namespace. The dev bootstrap regenerates this public configuration
from its existing deployment without redeploying contracts. Builds without pins
refuse new stablecoin swaps, but can still open existing recovery files. Forward
execution checks the deployed HTLC runtime before any approval or lock.

Sponsored completion requires the locally verified operation hash and staging
account, successful EntryPoint operation evidence, and the expected claim and
payout in that operation's receipt at settlement depth. An unrelated transfer
cannot prove completion. The sponsor still learns the preimage during preparation
and can withhold execution. After reload, older recovery files without operation
proof show a qualified claim observation, not verified sponsored completion.
Unknown exposure remains blocked from automatic retry.

Funded Bitcoin recovery checkpoints are saved encrypted in browser storage with
strict commit and exact readback before funding publication. On a URL-less reload,
open **History** below the swap card. Reverse swaps appear at every saved
stage; **Resume** continues funding checks and claims, never a Lightning payment.
Funded forward swaps open their refund controls locally. Merely listing swaps does
not connect, pay, sign, or broadcast. Keep a backup independently: browser eviction and
the interval before an external deposit is observed remain recovery risks.
Upgrades preserve existing recovery identities and counters, without retroactive
checkpoints or automatic network actions. Surviving checkpoints with a missing
identity cause a safe refusal, never a replacement key.

## Scripts

From `rill-web/`:

| Command | Purpose |
| --- | --- |
| `bun run typecheck` | Check TypeScript |
| `bun test unit` | Run unit tests |
| `bunx playwright install chromium` | Install the test browser |
| `bun run test` | Run browser tests |
| `bun run build` | Build the static site in `dist/` |
| `bun run build:pages` | Assemble the GitHub Pages site in `tmp/pages/` |
| `bun run test:pages` | Test the assembled Pages site |

Local builds and tests never publish anything.

## Using the app

The swap card shows only the current task. **History**, **Recovery**, **Providers**,
and **Settings** below it open separate panels without interrupting an active swap.
Settings and provider selection stay locked while a swap is running. Recovery
retains its separate inspection and approval controls. History can still be browsed,
but cannot open or resume a different swap until the current workflow releases its
lock. Privacy disclosures and technical activity are available in the footer.

Use **Back up your recovery key** to reveal or save the browser's 12 words.
This is recommended, not a prerequisite for swapping. Settings groups connection
endpoints, stablecoin configuration, limits, and advanced overrides into optional
disclosures. Saved history shows only what local records prove, not inferred
completion or dates. This layout does not migrate or replace existing keys,
checkpoints, journals, or encrypted swap links.

Pick a pair under **You send / You receive** (or use the switch button).
Available providers and their advertised assets decide which pairs can be
quoted.

Automatic provider choice ranks offers by the funding confirmations each
provider announces (fewest first), then by price. **Provider ranking** in
Settings switches to lowest price first. Providers that do not announce their
confirmations rank after those that do. The manual selection list labels the
fewest-confirmation and the cheapest offer, and the Providers panel shows each
provider's confirmations. An offer that waits longer than its provider
announced is refused. This ranking does not claim to select the fastest completion.
Use **Compare quotes** to inspect every returned Bitcoin quote and choose one
before proceeding, even when **Continue** would accept a price within the preview.

Bitcoin quote comparisons show the amount paid and received, maker service
fees or rebates, the maker's fixed mining allowance when itemized, and the
client's claim mining fee for Lightning to Bitcoin. The allowance is paid to
the maker, not passed through as its exact miner fee: the maker keeps savings
and covers differences in transaction costs. Legacy quotes without a breakdown
show a combined maker charge instead. Wallet deposit or Lightning routing fees
remain extra, and the claim mining fee is already included in the Lightning total.

Requesting Bitcoin quotes also reads public fee projections and recent blocks
from the configured chain API (no addresses, amounts, invoices, or keys are sent).
It never makes these reads on page load. Each quote shows a modeled chain-wait
range in minutes when fresh data supports one. Fee bands estimate queue position;
recent block cadence and an exponential-arrival model produce the 10th to 90th
percentile block-time range. This is conditional on current conditions and relay
acceptance, not a measured completion probability or a guarantee. It excludes
user and provider processing delays.

Bitcoin to Lightning estimates assume the wallet uses the API's recommended
deposit rate and end when the funding depth allows Lightning payment. Lightning
to Bitcoin estimates use the quoted funding-rate sample, or explicitly assume
the API's rate if absent, then include a subsequent first claim confirmation.
The claim estimate uses the larger script-path fallback; a key-path claim pays
the same reserve and can be faster. Quoted funding-rate estimates use the 154 vB
pricing model with whole-satoshi rounding when matching projected fee bands
(0.1 sat/vB becomes 16 sat for 154 vB). Funding-rate samples are not promises about
the eventual transaction. Stale or missing data, below-forecast rates, and
on-demand regtest mining show no clock estimate. Zero-confirmation forward
quotes show no confirmation wait; unconfirmed reverse packages are not modeled.
An explicit Bitcoin to Lightning block-height override skips optional timing
reads, preserving the existing offline/manual setup behavior.
These estimates do not change pricing, automatic selection, confirmation risk,
existing recovery records, or fee safety checks.

**Bitcoin to Lightning.** Paste the Lightning invoice to be paid. After
accepting the quote, send the exact amount to
the displayed contract address from any native segwit wallet (a `bitcoin:`
link and QR code are shown). Advanced users can supply a finalized PSBT. Do
not send extra or multiple deposits: deposits that break the funding rules
stop the swap and cannot currently be refunded from the panel. If the
provider pays at zero confirmations, the page binds your payment as soon as it
sees it. Do not bump its fee or replace it then: the replacement is not the
bound transaction, and you can only refund it after the refund height.

**Lightning to Bitcoin.** Enter the amount and Bitcoin address, accept the signed
price, and pay the invoice from any Lightning wallet (or a configured LND node).
The page checks the provider's funding and confirmations, then saves and broadcasts
the claim automatically. Keep the page open. The claim pays exactly the signed fee
reserve, so the address receives exactly the requested amount. Before asking for
signed terms, the page reads the chain API's next-block fee rate (`fastestFee`
from `/v1/fees/recommended`) and asks for a reserve that pays the larger
script-path claim at that rate, so the cooperative claim pays at least as much;
without an estimate, or if that reserve exceeds your maximum claim fee, it
stops before any payment. Live swaps first attempt a cooperative
key-path claim, keeping the script and preimage off chain. The signed unilateral
fallback is saved and its one-shot exposure journaled before the proposal can be
published. If cooperation stops before publication, the funding and claim safety
margin are checked again (up to three attempts for unknown reads). Once publication
may have revealed the preimage, the claim proceeds even if that margin passes or
chain reads fail. Cooperation has its own nonrenewing 30-second window, independent
of the original quote deadline. An interruption after journaling leaves only manual
fallback export on Resume, never another automatic broadcast. Upgrades preserve
existing records without inferring disclosure for older `claim-ready` swaps.
Advanced holds the fee details, one optional
latest swap backup, manual checks, and exact fallback export. The browser asks for
notification permission when you start a swap. Status notifications are enabled
when permission is granted; denying or dismissing the prompt does not block the
swap. No service worker is installed.

The invoice is a hold invoice. The provider locks the Bitcoin only after your
payment is held at its node for that exact payment hash, so an unpaid invoice
expires without locking anything. While the funding confirms, wallets without
hold invoice support may show the payment as pending, or as failed after their
own timeout, although it is still held. Do not pay again. After funding, the
page keeps **Your Lightning invoice** (text, QR, wallet link and payment hash)
for reference, and **Resume** shows it too.

By default the claim waits for the funding confirmations the provider signed
(at least 1). **Lightning to Bitcoin: claim after confirmations** in Settings
claims earlier, down to 0 (straight from the mempool), and the provider still
cooperates. The page shows a warning before you pay: the claim reveals the
payment secret, so the provider can settle your Lightning payment and then
double-spend its unconfirmed or shallow funding, keeping both. Only lower it
for providers and amounts you are willing to lose. Once the Bitcoin is locked,
Advanced also offers **Claim now from the mempool (risky)** behind the same
warning and a checkbox, on the open page and on Resume, for wallets that give
up waiting. Neither choice is stored: Resume and recovery wait for the signed
depth unless you choose again there. Claiming
at 0 needs a chain API that reports mempool outputs, as Esplora and mempool
do. The local dev chain API does not, so there the claim waits for the first
confirmation.

**USDC or USDT to Lightning.** Paste the Lightning invoice and connect an
injected EVM wallet on the provider's chain. Approve the token allowance if
needed and authorize the contract lock. The wallet keeps the refund key and
needs native gas.

**Lightning to USDC or USDT.** Choose the token payout and pay the displayed
invoice from any Lightning wallet. With a gas sponsor configured, just type
the receiving address; it needs no ETH. Without one, connect an injected EVM
wallet that receives the tokens and has gas for the claim. Claim promptly: a
failed wallet or sponsor request does not prove the preimage stayed private.

## Recovery

The app creates an origin-local recovery wallet. Saving its 12 words is
recommended, not required to swap. Tor Browser and private windows may erase
browser storage on restart. **The words alone cannot recover a swap**: the encrypted
swap record must also survive, in this browser, a swap link, or the optional latest
backup download (under Swap backup, or Advanced for Lightning to BTC). The words encrypt records; swap secrets are independently random.

Browser recovery keys are not encrypted at rest; same-origin scripts and
anyone with access to browser storage can read them. Do not clear browser
storage while funds are pending. The recovery wallet is not a general
spending wallet, and cloning it across devices can reuse addresses.

Use **Your swaps** to resume a saved reverse swap without any file. Unknown claim
submissions are watched, never submitted again; exact fallback export remains available.
A swap whose invoice was shown resumes with that invoice, open while the payment
is still unknown, so an interrupted payment can still be made once. Swaps saved
by earlier versions keep only the payment hash. A tab still running an earlier
version cannot list swaps saved with the invoice text; reload it.
Otherwise use **Recover a swap**, select the original network, and open the newest
backup or the bookmarked tracking link. On another device, enter the 12 words or
choose the JSON/age key backup. This does not replace the current browser key or
reset address counters. The link carries
an encrypted recovery container in its URL fragment (never sent to the
server); treat it like the file. Opening or reloading never retries payments,
claims or refunds by itself. Resume is explicit and never starts a new cooperative
nonce attempt.
CLI recovery files containing a reverse burn or preimage-disclosure record can
also be opened. They are authenticated as historical evidence, not signing
authority; a preexisting signed fallback remains UNKNOWN and export-only.

- **Bitcoin to Lightning refunds:** use **Check funding**, wait until the
  refund matures, review the destination and fee, then prepare, download
  and broadcast as separate explicit steps. Exporting the signed refund
  disables in-app broadcast.
- **Stablecoin to Lightning:** the wallet can refund after the contract
  timelock.
- **Lightning to stablecoin:** an unexposed swap can be claimed from the same
  browser. In another browser the imported file is inspection-only.

Bitcoin refunds also work with [rill-cli](../rill-cli/README.md) and a synced
Bitcoin Core node: download `rillswap-recovery.age-key` from the recovery
details and pass it as `--identity` to `rill recover watch-refund` or
`rill recover sign-refund`. The JSON mnemonic backup is not an age identity.

## Privacy and trust

| Service | What it can learn |
| --- | --- |
| Nostr relays | Your IP, keys used for messaging, message sizes and timing; swap payloads are encrypted |
| Swap provider | The swap terms and the invoice or payout details needed for the flow |
| Chain API | Your IP, the public transactions and outputs you query, and when you request fee estimates |
| Gas sponsor | The claim preimage and the receiving address |

Funding checks are observations from a trusted API, not independent
consensus verification. All runtime assets are bundled; the swap app only
connects to configured endpoints. The HTML meta CSP is not a full hosting
policy and does not prevent framing, so hosts must set real HTTP security
headers. There is no update check: reloading a hosted URL can run different
code, and the build label is not authenticated release pinning.

## Hosting

### GitHub Pages

The [Pages workflow](../.github/workflows/pages.yml) tests and deploys the
site on every push to `main` or when run manually; pull requests never
deploy. Set the repository's Pages source to **GitHub Actions**.
`bun run build:pages` produces `tmp/pages/` with:

- `/`: the mainnet app, with swaps enabled
- `/signet/`: the signet swap app
- `diagnostic.html` in each: the disconnected preview, marked `noindex`
- `sitemap.xml` and `robots.txt` at the root (crawlers read `robots.txt`
  only at a domain root, so it applies once the site has its own domain)

Each app page gets its own title and description, a canonical URL, Open Graph
and Twitter card tags pointing at `social-card.png`, and JSON-LD
`WebApplication` data linking the source repository. These absolute URLs
default to `https://rillswap.github.io/rillswap/`; a fork or custom domain
sets `RILLSWAP_SITE_URL` (ending in `/`) when running `bun run build:pages`.
The icons and social card live in `public/`.

The network indicator in the header is a picker: choosing mainnet or signet
opens the other build, and any other network reconfigures the current page
like Settings does. The Pages build ignores local `VITE_RILLSWAP_*` overrides
(it sets its own `VITE_RILLSWAP_DEPLOYMENTS`) so regtest endpoints never leak
into the public site. Local builds never publish.

### Serve locally

```sh
VITE_RILLSWAP_NETWORK=signet bun run build
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Open http://127.0.0.1:8080/swap.html. Opening files with `file://` is not
supported.

### Alchemy gas sponsor

The intended public-network sponsor is Alchemy's Wallet API:

| Setting | Value |
| --- | --- |
| Sponsor endpoint | `https://api.g.alchemy.com/v2/<key>` |
| EntryPoint | `0x0000000071727de22e5e9d8baf0edac6f37da032` |
| SMA7702 v1.1.0 delegate | `0x77021100bd87b7008e5e1989d0eb38555d0d0000` |
| Sponsor policy | Your gas policy UUID |

Restrict the API key to your site's origin. The policy may be omitted when a
proxy applies its own; unsponsored calls are refused. The sponsor flow is
tested against the local development stand-in, so verify Alchemy's responses
and browser CORS on a testnet before enabling it on mainnet.

## Opt-in tests

Regtest browser checks use `playwright.regtest.config.ts` and a running
disposable dev stack (see [DEVELOPMENT.md](../DEVELOPMENT.md)).

| Flag | Check | Needs |
| --- | --- | --- |
| `RILLSWAP_TEST_RECOVERY_NATIVE=1` | Native recovery, refund and reverse claim parity | Running `rillswap-dev-tools-1` container |
| `RILLSWAP_RUN_WEB_CLI_AGE=1` | Browser age files decrypted by Go age and the CLI | Chromium, local CLI, `RILL_CRYPTO_LIBRARY`, `AGE_BINARY` (Go age v1.3.1) |
| `RILLSWAP_RUN_BROWSER_REVERSE_REGTEST=1` | Funded Lightning to Bitcoin flow | Separate Compose project named `rill-reverse-browser-*` with a nondefault `RILL_DEV_WEB_PORT` |
| `RILLSWAP_RUN_BROWSER_ERC20_REGTEST=1` | Both stablecoin directions with a test EVM wallet | Dev stack with Anvil and dev tokens |

## Further reading

- [Protocol specifications](../rill-docs/specs/)
- [Architecture](../rill-docs/ARCHITECTURE.md)
- [Development and local testing](../DEVELOPMENT.md)
- [Security policy](../SECURITY.md)
