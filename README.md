# ops-monitor

Read-only mobile dashboard. Static page (no dependencies, strict CSP) that downloads an AES-256-GCM encrypted
snapshot from the `data` branch and decrypts it in the browser with a passphrase (PBKDF2-SHA256, 600k iterations).
The server publishes the snapshot every minute; the page cannot change anything anywhere.
