from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ScanLog:
    """
    자동 스캔 실행 로그 모델
    """

    source: str

    started_at: datetime

    finished_at: Optional[datetime]

    status: str

    scanned_target: str

    result_count: int

    error_message: Optional[str] = None