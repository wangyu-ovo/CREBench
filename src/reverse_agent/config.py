from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, validator


class InstanceMetadataConfig(BaseModel):
    generated_root: Path
    supported_key_modes: List[str] = Field(default_factory=list)
    default_key_mode: Optional[str] = None

    @validator("generated_root", pre=True)
    def validate_generated_root(cls, v):
        return Path(v)


class ChallengeConfig(BaseModel):
    # --- existing fields ---
    name: str
    public_path: Path = Field(..., alias='publc_path')
    flag: str
    flag_type: Optional[str] = None  # "hex" or None (text)

    # --- Level 1: algorithm identification ---
    algorithm: Optional[str] = None              # canonical name, e.g. "AES-128-CBC"
    algorithm_aliases: List[str] = Field(default_factory=list)  # acceptable alternatives

    # --- Level 2: key extraction ---
    key_material: Optional[str] = None           # e.g. "key=... iv=..."
    vulnerability_type: Optional[str] = None     # deprecated fallback for older configs
    vulnerability_details: Optional[str] = None  # deprecated fallback for older configs

    # --- Level 3: code recovery ---
    test_vectors_path: Optional[Path] = None     # path to test_vectors.json

    # --- metadata ---
    challenge_path: Optional[Path] = None
    key_mode: Optional[str] = None
    mode_variant: Optional[str] = None
    mode_metadata_path: Optional[Path] = None
    resolved_mode_metadata: Dict[str, Any] = Field(default_factory=dict)
    instance_metadata: Optional[InstanceMetadataConfig] = None
    difficulty: Optional[str] = None  # "easy", "medium", "hard"
    template_metadata: Dict[str, Any] = Field(default_factory=dict)
    tigress_metadata: Dict[str, Any] = Field(default_factory=dict)
    level3_validation: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True  # allow both 'publc_path' alias and 'public_path'

    @validator('public_path', pre=True)
    def validate_public_path(cls, v, values, **kwargs):
        return Path(v)

    @validator('test_vectors_path', pre=True)
    def validate_test_vectors_path(cls, v, values, **kwargs):
        if v is None:
            return None
        return Path(v)

    @validator("challenge_path", "mode_metadata_path", pre=True)
    def validate_optional_path(cls, v, values, **kwargs):
        if v is None:
            return None
        return Path(v)

    @property
    def level2_expected_material(self) -> Optional[str]:
        """Return the canonical Level 2 ground truth, with fallback for old configs."""
        return self.key_material or self.vulnerability_details


def _format_key_material_from_mode_metadata(metadata: Dict[str, Any]) -> Optional[str]:
    key_hex = metadata.get("key")
    if not key_hex:
        return None

    items = [f"key={key_hex}"]
    iv_hex = metadata.get("iv")
    if iv_hex:
        items.append(f"iv={iv_hex}")
    return " ".join(items)


def _repo_root_for_challenge(challenge_path: Path) -> Path:
    return challenge_path.resolve().parents[2]


def _resolve_repo_relative_path(challenge_path: Path, raw_path: Path | str | None) -> Optional[Path]:
    if raw_path is None:
        return None

    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()

    repo_root = _repo_root_for_challenge(challenge_path)
    repo_candidate = (repo_root / path).resolve()
    if repo_candidate.exists():
        return repo_candidate

    challenge_candidate = (challenge_path / path).resolve()
    if challenge_candidate.exists():
        return challenge_candidate

    return repo_candidate


def _resolve_static_paths(challenge_path: Path, config: ChallengeConfig) -> None:
    config.public_path = _resolve_repo_relative_path(challenge_path, config.public_path)
    if config.test_vectors_path is not None:
        config.test_vectors_path = _resolve_repo_relative_path(challenge_path, config.test_vectors_path)

    if config.instance_metadata is not None:
        config.instance_metadata.generated_root = _resolve_repo_relative_path(
            challenge_path,
            config.instance_metadata.generated_root,
        )


def _infer_default_key_mode(config: ChallengeConfig) -> Optional[str]:
    if config.instance_metadata and config.instance_metadata.default_key_mode:
        return config.instance_metadata.default_key_mode

    template_mode = config.template_metadata.get("key_generation_mode")
    if isinstance(template_mode, str) and template_mode.strip():
        return template_mode.strip()

    return None


def _resolve_mode_metadata(challenge_path: Path, config: ChallengeConfig, key_mode: Optional[str]) -> None:
    instance = config.instance_metadata
    if instance is None:
        if key_mode:
            raise ValueError(f"{challenge_path.name}: key mode '{key_mode}' requested but config has no instance_metadata")
        return

    selected_mode = key_mode or _infer_default_key_mode(config)
    if not selected_mode:
        return

    if instance.supported_key_modes and selected_mode not in instance.supported_key_modes:
        allowed = ", ".join(instance.supported_key_modes)
        raise ValueError(f"{challenge_path.name}: unsupported key mode '{selected_mode}', expected one of: {allowed}")

    metadata_path = instance.generated_root / selected_mode / "metadata.json"
    if not metadata_path.exists():
        raise FileNotFoundError(f"{challenge_path.name}: missing mode metadata: {metadata_path}")

    with open(metadata_path, "r", encoding="utf-8") as f:
        mode_metadata = yaml.safe_load(f)
    if not isinstance(mode_metadata, dict):
        raise ValueError(f"{challenge_path.name}: invalid mode metadata in {metadata_path}")

    config.key_mode = selected_mode
    config.mode_metadata_path = metadata_path
    config.mode_variant = mode_metadata.get("variant")
    config.resolved_mode_metadata = mode_metadata

    metadata_mode = mode_metadata.get("key_mode")
    if metadata_mode and metadata_mode != selected_mode:
        raise ValueError(
            f"{challenge_path.name}: metadata key_mode mismatch in {metadata_path}: "
            f"expected {selected_mode}, got {metadata_mode}"
        )

    metadata_flag = mode_metadata.get("flag")
    if metadata_flag and str(metadata_flag).strip().lower() != config.flag.strip().lower():
        raise ValueError(
            f"{challenge_path.name}: metadata flag mismatch in {metadata_path}"
        )

    derived_key_material = _format_key_material_from_mode_metadata(mode_metadata)
    if derived_key_material:
        config.key_material = derived_key_material

    test_vectors_path = mode_metadata.get("test_vectors_path")
    if test_vectors_path:
        config.test_vectors_path = _resolve_repo_relative_path(challenge_path, test_vectors_path)


def _resolve_public_path(challenge_path: Path, config: ChallengeConfig, difficulty: Optional[str]) -> None:
    if not difficulty:
        return

    candidates: List[Path] = []
    if config.key_mode:
        candidates.append(challenge_path / f"public-{config.key_mode}-{difficulty}")
    candidates.append(challenge_path / f"public-{difficulty}")

    for candidate in candidates:
        if candidate.exists():
            config.public_path = candidate.absolute()
            config.difficulty = difficulty
            return

    tried = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"{challenge_path.name}: difficulty '{difficulty}' requested but no public directory found. tried: {tried}")


def load_config(challenge_path: Path, key_mode: Optional[str] = None, difficulty: Optional[str] = None) -> ChallengeConfig:
    config_path = challenge_path / 'config.yaml'
    with open(config_path, 'r') as f:
        data = yaml.safe_load(f)
    config = ChallengeConfig(**data)
    config.challenge_path = challenge_path.resolve()
    _resolve_static_paths(challenge_path, config)
    _resolve_mode_metadata(challenge_path, config, key_mode)
    _resolve_public_path(challenge_path, config, difficulty)
    return config
