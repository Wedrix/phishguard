# Backup and restoration runbook

Cloud SQL uses daily backups, seven days of transaction logs/PITR, 30 retained backups, and deletion protection. Artefact storage is versioned. Backups are encrypted but may retain deleted user data until expiry.

## Quarterly rehearsal

1. Record source instance, chosen recovery timestamp, schema revision, image/model/policy digests, and start time.
2. Restore to a new isolated Cloud SQL instance with private IP. Never overwrite the active instance.
3. Grant only the rehearsal workload IAM user, connect through Cloud SQL Auth Proxy, and run migration status plus read-only integrity checks: table counts, foreign keys, latest job leases, audit-chain verification, and one redacted known scan.
4. Deploy a temporary web/jobs pair with enrichment disabled and no public Gateway. Verify sign-in, authorised history, result rendering, and cleanup against the restored database.
5. Record recovery point, recovery time, discrepancies, and evidence. Delete the temporary workload and instance through an approved change after preserving the report.

If recovery is required during an incident, keep the old instance read-only, update the connection target through an approved deployment, validate before DNS traffic restoration, and retain both audit trails. Never disable deletion protection merely to speed recovery.

