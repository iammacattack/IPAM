-- Site retire and purge (spec §5.7, FR-14).
-- Retire: the site code is freed at once; the address space stays held (blocks kept) until the
-- quarantine ends, so addresses still in DNS, firewall rules or device configs aren't reissued.
ALTER TABLE site ADD COLUMN retired_at timestamptz;
ALTER TABLE site ADD COLUMN retired_by text;
ALTER TABLE site ADD COLUMN retire_reason text;
ALTER TABLE site ADD COLUMN change_ref text;
ALTER TABLE site ADD COLUMN quarantine_until timestamptz;
ALTER TABLE site ADD COLUMN space_released_at timestamptz;
