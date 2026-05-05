-- Recovery / readiness columns on biometrics for ELH Health.
-- Mirrors elh-coach 0008 — drives daily readiness score
-- (fitapp_core.recovery_score) plus member-side trend cards.

alter table biometrics add column if not exists hrv_rmssd_ms numeric(5,1);
alter table biometrics add column if not exists sleep_hours  numeric(3,1);
alter table biometrics add column if not exists steps        int;
alter table biometrics add column if not exists active_kcal  int;
