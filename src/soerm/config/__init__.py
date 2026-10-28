"""Workspace configuration: the only place that reads YAML."""

from soerm.config.errors import ConfigError
from soerm.config.loader import (
    CONFIG_FILE_NAME,
    MAX_CONFIG_BYTES,
    config_path,
    load_config,
    load_yaml_text,
)
from soerm.config.schema import CONFIG_VERSION, SoermConfig, parse_config

__all__ = [
    "CONFIG_FILE_NAME",
    "CONFIG_VERSION",
    "MAX_CONFIG_BYTES",
    "ConfigError",
    "SoermConfig",
    "config_path",
    "load_config",
    "load_yaml_text",
    "parse_config",
]
