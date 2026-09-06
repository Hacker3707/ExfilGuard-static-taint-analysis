from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DetectionResult:
    source: str
    source_category: str     # S_ctx, S_prog, S_dyn, S_inp, S_env
    sink: str
    sink_category: str       # K_cli, K_lib, K_dns, K_raw, K_scm
    destination_type: str    # untrusted_external, allowlisted, external
    risk_score: float
    risk_level: str
    command: str
    context: str
    path: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "Source": self.source,
            "Source_Category": self.source_category,
            "Sink": self.sink,
            "Sink_Category": self.sink_category,
            "Destination_Type": self.destination_type,
            "Risk_Score": self.risk_score,
            "Risk_Level": self.risk_level,
            "Command": self.command,
            "Context": self.context,
            "Path": self.path,
        }