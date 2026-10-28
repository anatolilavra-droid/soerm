"""Safe loading of ``<workspace>/soerm.yaml``.

* only the file inside the workspace, a regular file (no symlink, device or FIFO);
* at most :data:`MAX_CONFIG_BYTES` are read; UTF-8 only;
* ``yaml.SafeLoader`` subclass: no anchors, no aliases, no merge keys, no explicit tags of
  any kind (so no custom or language-specific tags), no duplicate keys, string keys only,
  exactly one document;
* every parser message is dropped: YAML errors quote the offending text, which could be a
  secret. Errors carry stable reason codes only.
"""

import os
import stat
from pathlib import Path
from typing import Any, Final

import yaml

from soerm.config.errors import ConfigError
from soerm.config.schema import CONFIG_VERSION, SoermConfig, parse_config

__all__ = ["CONFIG_FILE_NAME", "MAX_CONFIG_BYTES", "config_path", "load_config", "load_yaml_text"]

CONFIG_FILE_NAME: Final = "soerm.yaml"
MAX_CONFIG_BYTES: Final = 65536
_MERGE_TAG: Final = "tag:yaml.org,2002:merge"


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses everything that is not plain data."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise ConfigError("yaml_alias")
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if getattr(event, "anchor", None) is not None:
            raise ConfigError("yaml_anchor")
        if getattr(event, "tag", None) is not None:
            raise ConfigError("yaml_tag")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _ in node.value:
            if key_node.tag == _MERGE_TAG:
                raise ConfigError("yaml_merge_key")
            if not isinstance(key_node, yaml.ScalarNode) or key_node.tag != "tag:yaml.org,2002:str":
                raise ConfigError("yaml_key_not_string")
            if key_node.value in seen:
                raise ConfigError("yaml_duplicate_key")
            seen.add(key_node.value)
        return super().construct_mapping(node, deep=deep)


def load_yaml_text(text: str) -> object:
    """Parse one YAML document with the strict loader."""
    loader = _StrictLoader(text)
    try:
        return loader.get_single_data()
    except ConfigError:
        raise
    except RecursionError:
        raise ConfigError("yaml_too_deep") from None
    except yaml.YAMLError:
        raise ConfigError("yaml_syntax") from None
    finally:
        loader.dispose()


def config_path(workspace: Path) -> Path:
    return workspace / CONFIG_FILE_NAME


def _read_limited(path: Path) -> str | None:
    """File text, or ``None`` if the file does not exist."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError:
        raise ConfigError("config_unreadable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("config_not_regular_file")
        if info.st_size > MAX_CONFIG_BYTES:
            raise ConfigError("config_too_large")
        raw = os.read(descriptor, MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ConfigError("config_unreadable") from None
    finally:
        os.close(descriptor)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("config_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("config_not_utf8") from None
    text = text.removeprefix("﻿")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise ConfigError("config_control_character")
    return text


def load_config(workspace: Path) -> tuple[SoermConfig, bool]:
    """Load ``<workspace>/soerm.yaml``; returns (config, file_found).

    A missing file is not an error: the built-in defaults apply.
    """
    text = _read_limited(config_path(workspace))
    if text is None:
        return SoermConfig(version=CONFIG_VERSION), False
    data = load_yaml_text(text)
    if data is None:
        raise ConfigError("config_empty")
    return parse_config(data), True
