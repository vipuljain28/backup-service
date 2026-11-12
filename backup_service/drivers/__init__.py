"""Source Driver Factory."""

from backup_service.config.settings import ClientConfig
from backup_service.drivers.base import SourceDriver
from backup_service.drivers.local_driver import LocalDriver
from backup_service.drivers.ssh_driver import SSHDriver


def get_source_driver(client_config: ClientConfig) -> SourceDriver:
    """Instantiate appropriate SourceDriver based on ClientConfig connection mode."""
    if client_config.connection_mode == "local":
        return LocalDriver()
    elif client_config.connection_mode == "ssh":
        if not client_config.ssh:
            raise ValueError(f"Client '{client_config.client_id}' is configured with 'ssh' mode but lacks ssh config.")
        return SSHDriver(client_config.ssh)
    else:
        raise ValueError(f"Unknown connection_mode: {client_config.connection_mode}")
