-- 0249 (CONTRACT): the station-less export marker from 0246 is replaced by
-- mark_sdm_batch_exported(uuid, uuid) from 0248. Applied after production
-- reported schema 0248.
revoke all on function vault_enclave.mark_sdm_batch_exported(uuid) from public, rout_app;
drop function vault_enclave.mark_sdm_batch_exported(uuid);
