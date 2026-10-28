"""Full-screen terminal UI (M13): a read-only window onto the existing services.

The UI never opens the database, never builds SQL, never starts a process and never changes a
domain object. Everything it shows comes from :mod:`soerm.tui.data`, which calls the service
layer and cleans every string (redaction again, no control characters, no markup).
"""
