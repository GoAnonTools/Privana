import logging
import platform


log = logging.getLogger("privana.endpoint_check")


class EndpointChecker:
    """
    Endpoint integrity checks are currently not implemented.

    Previous versions compared SHA-256(platform string) to a hardcoded value.
    That was not a real integrity/attestation mechanism and could give users
    false confidence. Until real attestation exists, this checker only verifies
    basic OS support and reports integrity attestation as unavailable.
    """

    def __init__(self):
        self.os_info = f"{platform.system()} {platform.release()}"

    def check(self) -> bool:
        """
        Return True only for basic OS support.

        This is intentionally NOT a security attestation. It must not be shown
        to users as proof that the endpoint is uncompromised.
        """
        supported = self._check_os()
        if not supported:
            log.warning("Unsupported OS for Privana endpoint. os_info=%s", self.os_info)
            return False

        log.info("Endpoint integrity attestation unavailable; only OS support checked.")
        return True

    def status(self) -> dict:
        """Machine-readable status for UI/debugging."""
        return {
            "supported_os": self._check_os(),
            "os_info": self.os_info,
            "integrity_attestation": "unavailable",
            "security_claim": "none",
        }

    def _check_os(self) -> bool:
        supported_os = {"Linux", "Darwin", "Windows"}
        return platform.system() in supported_os
