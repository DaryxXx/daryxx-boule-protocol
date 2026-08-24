class ProtocolError(ValueError):
    """Raised when an event or artifact violates the frozen protocol."""


class AuthenticationError(ProtocolError):
    """Raised when a remote participant signature cannot be authenticated."""


class StaleHeadError(ProtocolError):
    """Raised when a signed remote envelope targets an older event head."""

    def __init__(self, current_head: str | None, event_count: int) -> None:
        super().__init__("remote envelope was signed against a stale event head")
        self.current_head = current_head
        self.event_count = event_count


class RequestConflictError(ProtocolError):
    """Raised when one remote request id is reused for different signed bytes."""


class RemoteTransportError(ProtocolError):
    """Raised when remote receipt status is unavailable or ambiguous."""
