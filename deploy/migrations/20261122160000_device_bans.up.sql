-- device_bans lets an admin block a device fingerprint so that if its owner's
-- account is banned and they sign up again on the same device, the new
-- account cannot be created through that fingerprint. The fingerprint is a
-- hash of auth.Authorization's DeviceModel+SystemVersion+Platform+APIID
-- (see domain.DeviceFingerprint), not the IP -- IP changes too often to be a
-- stable device identity and would false-positive shared networks.
CREATE TABLE IF NOT EXISTS public.device_bans (
    fingerprint    text PRIMARY KEY,
    banned_user_id bigint NOT NULL,
    reason         text NOT NULL DEFAULT '',
    actor          text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);
