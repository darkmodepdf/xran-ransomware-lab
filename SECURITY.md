# Security

This is a local controlled research laboratory, not production endpoint protection. Its normal service binds to localhost; separate control/agent credentials protect operations. Keep its session URL and credential files private. Do not expose the port externally.

Report a suspected vulnerability privately to the repository owner through an existing private channel, or use GitHub private vulnerability reporting if enabled. Include a minimal reproducible description, affected revision and redacted logs. Do not publish working credentials, user file contents or raw reports in an issue.

If a session credential is exposed, stop that owned lab session and start a new session with fresh credentials. Do not alter unrelated services. If unexpected entries or links block fixture cleanup, preserve the error evidence and inspect the verified owned root before cleanup.

Security changes should preserve independent actor histories, strict Origin/Host/authentication checks, bounded event/state queues, fixed owned fixture inventories and safe subprocess ownership. A missed model alert or the saved two benign false alerts are research limitations; an escape from these ownership or authentication boundaries is a security concern.
