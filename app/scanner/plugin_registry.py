import importlib
import inspect
import logging
import pkgutil
from app.scanner.plugin_base import BaseScannerPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    def __init__(self):
        self._plugins: dict[str, BaseScannerPlugin] = {}

    def register(self, plugin: BaseScannerPlugin) -> None:
        self._plugins[plugin.meta.id] = plugin
        logger.debug("Registered plugin: %s", plugin.meta.id)

    def get(self, plugin_id: str) -> BaseScannerPlugin | None:
        return self._plugins.get(plugin_id)

    def list_default(self) -> list[BaseScannerPlugin]:
        return list(self._plugins.values())


registry = PluginRegistry()


def _autodiscover():
    """Import all modules in app/scanner/plugins/ and register BaseScannerPlugin subclasses."""
    import app.scanner.plugins as plugins_pkg

    for _importer, module_name, _ispkg in pkgutil.iter_modules(plugins_pkg.__path__):
        full_name = f"app.scanner.plugins.{module_name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as exc:
            logger.warning("Failed to import plugin module %s: %s", full_name, exc)
            continue

        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                obj is not BaseScannerPlugin
                and issubclass(obj, BaseScannerPlugin)
                and hasattr(obj, "meta")
            ):
                try:
                    instance = obj()
                    registry.register(instance)
                except Exception as exc:
                    logger.warning("Failed to instantiate plugin %s: %s", obj.__name__, exc)


_autodiscover()
