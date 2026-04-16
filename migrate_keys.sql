-- Migration Script: Import old keys from keys.json to D1
-- Run this command in your terminal:
-- npx wrangler d1 execute kleslwr-license-db --file=migrate_keys.sql

-- Key: KLES-DEF1-3E0C-A4DD
INSERT OR IGNORE INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, expires_at, created_at, updated_at)
VALUES ('lic_migrate_1', 'HASH_PLACEHOLDER_1', 'KLES', 'A4DD', 'Monthly', 'premium', 'active', '1189581695842779228', 'cs_test_a12k42k9nqd6tO6mkjKch8sUWDEUmKpNcnOdQdmHdiVW4A8V3k70Zv4D9M', 'cus_UJMCX9bTntleZE', 1, 1712743736000, 1715335736000, 1712743736000, 1712743736000);

-- Key: KLES-13E0-8FB2-D132
INSERT OR IGNORE INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, expires_at, created_at, updated_at)
VALUES ('lic_migrate_2', 'HASH_PLACEHOLDER_2', 'KLES', 'D132', 'Trial', 'free', 'active', 'free-test-user', 'free_loot-1776181811391', NULL, 1, 1713109812000, 1713196211000, 1713109812000, 1713109812000);

-- Key: KLES-A8C2-BD96-96A2
INSERT OR IGNORE INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, expires_at, created_at, updated_at)
VALUES ('lic_migrate_3', 'HASH_PLACEHOLDER_3', 'KLES', '96A2', 'Trial', 'free', 'active', 'free-test-user-2', 'free_loot-1776181883464', NULL, 1, 1713109883000, 1713196283000, 1713109883000, 1713109883000);

-- IMPORTANT: You must replace HASH_PLACEHOLDER_X with the SHA256(LICENSE_PEPPER + ":" + KEY)
-- Since I don't know your LICENSE_PEPPER, you should generate these hashes or just re-issue the keys.
