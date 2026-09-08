from dataclasses import dataclass, field
from typing import List

# ==============================================================================
# FINDING TYPES
# ==============================================================================
# Tach loai finding ra khoi risk score. Truoc day moi thu deu la "detection",
# nen mot luong da duoc chung minh KHONG phai exfil van mang diem CRITICAL chi
# vi source la secret - do chinh la co che sinh ra FP.
#
#   EXFIL               Du lieu tainted roi runner qua kenh mang. Day la cai
#                       ma rule exfil dang do.
#   EXPOSURE            Du lieu tainted bi publish (git push, artifact, S3).
#   SUPPLY_CHAIN        Mutable ref tren action phat hanh credential.
#   CREDENTIAL_EXCHANGE Secret trong payload nhung la trao doi OAuth hop le.
#   INFO                Secret dung lam dia chi dich. Khong phai exfil.

FINDING_EXFIL = "EXFIL"
FINDING_EXPOSURE = "EXPOSURE"
FINDING_SUPPLY_CHAIN = "SUPPLY_CHAIN"
FINDING_CREDENTIAL_EXCHANGE = "CREDENTIAL_EXCHANGE"
FINDING_INFO = "INFO"
FINDING_FILE_EXFIL = "FILE_EXFIL"   # file-mediated: payload di qua file

ALL_FINDING_TYPES = (
    FINDING_EXFIL,
    FINDING_FILE_EXFIL,
    FINDING_EXPOSURE,
    FINDING_SUPPLY_CHAIN,
    FINDING_CREDENTIAL_EXCHANGE,
    FINDING_INFO,
)

# Cac loai tra loi dung cau hoi "co exfil khong". Dung tap nay khi cham
# benchmark cua rule exfil; SUPPLY_CHAIN va CREDENTIAL_EXCHANGE la van de that
# nhung thuoc rule khac nen phai loc ra keo bi tinh la FP.
EXFIL_CLASS_TYPES = (FINDING_EXFIL, FINDING_FILE_EXFIL, FINDING_EXPOSURE)

# Tran diem theo loai finding. Mot finding INFO khong duoc mang diem HIGH.
FINDING_TYPE_SCORE_CAP = {
    FINDING_INFO: 1.5,
    FINDING_CREDENTIAL_EXCHANGE: 3.5,
    FINDING_SUPPLY_CHAIN: 7.0,
}

# Nguong lay tu engine.common de chi co MOT nguon su that. Truoc day models
# dung 8.5/6.5 con common dung 8.0/6.0 -> hai cho phan loai lech nhau.
from engine.common import level_for_score  # noqa: E402


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

    # Mac dinh EXFIL de moi loi goi constructor cu chay nguyen ven.
    finding_type: str = FINDING_EXFIL
    note: str = ""

    def __post_init__(self):
        cap = FINDING_TYPE_SCORE_CAP.get(self.finding_type)
        if cap is not None and self.risk_score > cap:
            self.risk_score = cap
            self.risk_level = level_for_score(cap)

    @property
    def is_exfil_class(self) -> bool:
        return self.finding_type in EXFIL_CLASS_TYPES

    def to_dict(self):
        return {
            "Finding_Type": self.finding_type,
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
            "Note": self.note,
        }