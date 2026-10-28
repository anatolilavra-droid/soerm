"""Read-only check of the audit hash chain (``soerm audit verify``).

Nothing is written: no lock, no audit entry. A broken chain is a result (not an exception), so
the caller can show where it breaks; only the position and a reason code are reported.
"""

from soerm.domain.errors import IntegrityDomainError
from soerm.domain.report import AuditFacts
from soerm.services.workspace import Workspace
from soerm.storage.audit import get_audit_head, verify_audit_chain

__all__ = ["verify_workspace_audit"]


def verify_workspace_audit(workspace: Workspace) -> AuditFacts:
    with workspace.read() as session:
        try:
            head = verify_audit_chain(session.connection)
        except IntegrityDomainError as exc:
            head = get_audit_head(session.connection)
            raw_seq = str(exc.details.get("seq", ""))
            return AuditFacts(
                False,
                head.seq,
                head.entry_hash,
                int(raw_seq) if raw_seq.isdigit() else None,
                str(exc.details.get("reason", "integrity")),
            )
        return AuditFacts(True, head.seq, head.entry_hash)
