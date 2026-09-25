// Give your agent an ERC-8004 identity on Arc for free, from your own wallet.
// Your key stays on your machine: this script signs locally and only ever sends the signed transaction to an Arc RPC.
//   PRIVATE_KEY=0x... node examples/free-self-mint.mjs "My Agent" "What it does, in a sentence." https://my-agent.example/.well-known/agent-card.json
// Needs about 0.004 USDC of gas on Arc (free claim: https://apexfaucet.xyz/arc/faucet/).
import { createWalletClient, createPublicClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const API = process.env.PASSPORT_API || 'https://apexfaucet.xyz';
const [name, description, a2a] = process.argv.slice(2);
if (!process.env.PRIVATE_KEY || !name || !description) { console.error('usage: PRIVATE_KEY=0x... node free-self-mint.mjs "Name" "Description" [A2A card URL]'); process.exit(2); }
const arc = defineChain({ id: 5042, name: 'Arc', nativeCurrency: { name: 'USDC', symbol: 'USDC', decimals: 18 }, rpcUrls: { default: { http: ['https://rpc.mainnet.arc.io'] } } });
const account = privateKeyToAccount(process.env.PRIVATE_KEY);
const wallet = createWalletClient({ chain: arc, transport: http(), account });
const pub = createPublicClient({ chain: arc, transport: http() });

const draft = await (await fetch(API + '/api/arc/passport/draft', { method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name, description, services: a2a ? [{ name: 'A2A', endpoint: a2a }] : [] }) })).json();
if (!draft.ok) throw new Error(draft.error);
console.log('registration file:', draft.agentURI, draft.active ? '(an endpoint answered)' : '(no endpoint answered: active=false)');
if (draft.register.to.toLowerCase() !== '0x8004a169fb4a3325136eb29fa0ceb6d2e539a432') throw new Error('unexpected target contract');
const hash = await wallet.sendTransaction({ to: draft.register.to, data: draft.register.data });
await pub.waitForTransactionReceipt({ hash });
console.log('register() sent:', hash);
for (let i = 0; i < 20; i++) {
  const r = await fetch(API + '/api/arc/passport/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ slug: draft.slug, tx: hash }) });
  const j = await r.json();
  if (j.ok) { console.log('agent #' + j.passport.agentId + ' is yours:', j.passport.links.passport); process.exit(0); }
  if (r.status !== 202) throw new Error(j.error);
  await new Promise((res) => setTimeout(res, 2000));
}
