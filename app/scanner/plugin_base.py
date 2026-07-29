from dataclasses import dataclass, field


@dataclass
class PluginMeta:
    id: str
    display_name: str
    timeout_seconds: int = 60
    requires_root: bool = False
    safe_to_retry: bool = True


@dataclass
class PluginResult:
    plugin_id: str
    target: str
    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    error: str | None = None
    duration_seconds: float = 0.0


class BaseScannerPlugin:
    meta: PluginMeta

    def run(self, target: str, options: dict) -> PluginResult:
        raise NotImplementedError
