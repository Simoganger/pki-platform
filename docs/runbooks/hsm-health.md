# Runbook — HSM health and custodian changes

**Triggers**: Datadog `[PKI] HSM not answering SNMP`, SNMP traps (hardware, authentication
failure), Splunk `PKI - HSM authentication failures`.

## 1. HSM not answering SNMP

| Check | Command / place |
| --- | --- |
| Relay host reachable and Agent running | `sudo datadog-agent status` (SNMP section) |
| SNMPv3 credentials still valid (rotation?) | `observability/datadog-agent/test-snmpv3.sh <ip> dd-monitor` |
| Network path / ACL | firewall logs between relay and HSM management interface (UDP 161) |
| HSM itself | vendor console: Thales `lunash:> hsm show` / Utimaco `csadm GetState` |

If the HSM is down: fail over to the HA peer (Luna HA group / Utimaco cluster); for the
offline root, this is not urgent unless a ceremony is scheduled.

## 2. Authentication failures

Several failures on the SO / Crypto Officer role outside a ceremony = **security incident**
(`security-tripwire.md`). Many vendors lock or zeroize partitions after repeated failures:
check the lockout counter before any retry.

## 3. Custodian (M-of-N) change

When a key custodian leaves or changes role:

1. HR offboarding notifies the PKI team (control).
2. Recover the authentication part (PED key / smart card) with a witness; if it cannot be
   recovered, treat it as compromised.
3. Planned ceremony to re-share the authentication secret to a new custodian set and
   invalidate the old parts (the protected key does not change, only its activation
   material).
4. Update the custodian register; keep the minutes as PCI DSS 3.6/3.7 evidence.

Keep N comfortably above M (e.g. 3 of 5) so one departure never blocks a ceremony.

## 4. Firmware / FIPS status

Before any firmware upgrade, confirm the target version is covered by a valid
**FIPS 140-3** certificate (NIST CMVP) and that the HSM stays in its approved mode.
