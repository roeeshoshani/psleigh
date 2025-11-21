from __future__ import annotations

from typing import Any
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

class NonPureWheelBuildHook(BuildHookInterface):
    PLUGIN_NAME = "non-pure-wheel-build-hook"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # only care about wheel builds, not sdist
        if self.target_name != "wheel":
            return

        build_data["pure_python"] = False
        build_data["infer_tag"] = True
