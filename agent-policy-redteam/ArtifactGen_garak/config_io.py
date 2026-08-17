"""Compatibility aliases for ArtifactGen_garak.artifact_io."""

from .artifact_io import (  # noqa: F401
    DEFAULT_ARTIFACT_DIR,
    artifact_path_for,
    load_artifact,
    realized_to_artifact,
    save_artifact,
)

DEFAULT_CONFIG_DIR = DEFAULT_ARTIFACT_DIR
config_path_for = artifact_path_for
realized_to_config = realized_to_artifact
save_config = save_artifact
load_config = load_artifact
