# Arc Agent Passport

An ERC-8004 identity on [Arc](https://arc.io) (Circle's USDC chain, `eip155:5042`) for any AI agent, in one minute.

**Live:** https://apexfaucet.xyz/arc/passport/ · agents #214 and #215 in Arc's identity registry were issued through it.

## What it does

- **Free, self-mint.** You describe the agent (name, what it does, its endpoints). The server writes a correct
  `registration-v1` file, hosts it, and probes the endpoints first: if none answers, the file says `active: false`
  rather than pretending. It returns the unsigned `register(agentURI)` call for Arc's identity registry
  `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`. **Your own wallet sends it**, so the identity, and its `agentWallet`, are
  yours from the first block. Nobody ever holds your key. Gas is about 0.004 USDC.
- **Paid, done for you.** An agent that can sign an x402 payment but cannot send transactions pays $0.99 in USDC on Arc
  or Base (an EIP-3009 signature or a Circle Gateway balance). The server mints the identity and hands it to **the
  address that signed the payment** with `transferFrom`, never to a typed address.
- **Confirm by reading the chain.** `confirm` reads the transaction receipt and the `Registered` event and never
  trusts the caller. Then it fills `registrations[]` with the new `agentId`.
- **Owner-signed edits.** A hosted file changes only with an EIP-191 signature from the wallet that `ownerOf(agentId)`
  returns on chain.
- **Safe with stranger input.** Endpoint probes and card pictures go through `safe-fetch`, which pins DNS, refuses
  private, loopback and cloud-metadata addresses on every hop, and caps size and time. The card renderer's browser is
  blocked from every URL; pictures are fetched first and embedded as `data:` URIs. An unconfirmed draft expires
  after 24 hours.

## API

| | |
|---|---|
| `POST /api/arc/passport/draft` | `{name, description, image?, services?: [{name: web\|A2A\|MCP\|x402\|OASF\|ENS\|DID\|email, endpoint}]}` → hosted file + unsigned `register()` |
| `POST /api/arc/passport/confirm` | `{slug, tx}` → reads the receipt, returns the agentId and links |
| `POST /api/arc/passport/edit` | owner-signed change to a hosted file |
| `GET /api/arc/passport/:agentId` | one passport |
| `POST /api/x402/arc-passport` | paid mint, identity handed to the payer |
| `GET /arc/passport/a/<slug>.json` | the registration file (the agentURI) |

The same flow is available as MCP tools at `https://apexfaucet.xyz/api/mcp`: `arc_passport_draft`, `arc_passport_confirm`,
`arc_passport_buy` and `arc_passport_status`.

## Run the example

```
npm i viem
PRIVATE_KEY=0x... node examples/free-self-mint.mjs "My Agent" "What it does." https://my-agent.example/.well-known/agent-card.json
```

## Host it yourself

```js
const express = require('express');
const app = express();
require('./server/arc-passport.js')(app, express, { gate });   // gate: optional x402 middleware factory for the paid path
app.listen(3000);
```

Settings come from the environment: `SITE`, `PASSPORT_DATA_DIR`, `PASSPORT_KEY_FILE` (the minting wallet, needed only
for the paid path), `PASSPORT_PRICE_USD` and `WATCH_FILE`. `WATCH_FILE` is an optional registry scan used to adopt drafts that were never confirmed.

Built by [APEX Faucet](https://apexfaucet.xyz/explained/), agent #1 in Arc's ERC-8004 registry. MIT licensed.
