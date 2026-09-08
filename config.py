from dataclasses import dataclass, field
from typing import Tuple

from engine.models import ALL_FINDING_TYPES, EXFIL_CLASS_TYPES

LEVEL_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class ExfilGuardConfig:
    """Configuration to toggle analyzers for Ablation Studies."""

    enable_yaml: bool = True
    enable_bash: bool = True
    enable_python: bool = True
    enable_nodejs: bool = True
    min_risk_level: str = "MEDIUM"

    # SRC-03/04/05: khop lexical qualifier tren ten bien. Tat mac dinh vi bat
    # len se coi moi bien ten *KEY* la nhay cam (CACHE_KEY, SORT_KEY...).
    enable_lexical_source: bool = False  # LOW, MEDIUM, HIGH, CRITICAL

    # Loai finding duoc bao cao. Khi cham benchmark cua rule exfil, dat
    # report_finding_types = EXFIL_CLASS_TYPES de SUPPLY_CHAIN va
    # CREDENTIAL_EXCHANGE khong bi tinh nham thanh FP.
    report_finding_types: Tuple[str, ...] = field(
        default_factory=lambda: tuple(ALL_FINDING_TYPES)
    )

    def should_report(self, detection) -> bool:
        """Loc mot DetectionResult theo ca finding_type lan risk level."""
        if detection.finding_type not in self.report_finding_types:
            return False
        try:
            floor = LEVEL_ORDER.index(self.min_risk_level)
            actual = LEVEL_ORDER.index(detection.risk_level)
        except ValueError:
            return True
        return actual >= floor


# Default: Full-system configuration
DEFAULT_CONFIG = ExfilGuardConfig()

# Che do cham benchmark rule exfil: chi EXFIL + EXPOSURE, khong loc theo level
# (de mot EXFIL diem thap van duoc tinh la DETECTED).
BENCHMARK_EXFIL_CONFIG = ExfilGuardConfig(
    min_risk_level="INFO",
    report_finding_types=tuple(EXFIL_CLASS_TYPES),
)