const { execSync } = require('child_process');
const id = '412981446449914375'; // user's discord ID
const ts = Date.now();
const cmd = `npx wrangler d1 execute kleslwr-license-db --remote --command="INSERT INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, created_at, updated_at, plain_key) VALUES ('lic_mock_${ts}', 'fake', 'KLESP', '9999', 'Lifetime', 'premium', 'active', '${id}', 'mock', 'stripe', 1, ${ts}, ${ts}, ${ts}, 'KLESP-MOCK-XXXX-XXXX-XXXX')"`;
execSync(cmd, {stdio: 'inherit'});
