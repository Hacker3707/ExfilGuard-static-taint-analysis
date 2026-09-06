from dataclasses import dataclass

@dataclass
class ExfilGuardConfig:
    """Configuration to toggle analyzers for Ablation Studies."""
    enable_yaml: bool = True
    enable_bash: bool = True
    enable_python: bool = True
    enable_nodejs: bool = True
    min_risk_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL

# Default: Full-system configuration
DEFAULT_CONFIG = ExfilGuardConfig()