from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class ScanLog:

    source: str

    started_at: datetime

    finished_at: Optional[datetime]

    status: str

    scanned_target: str

    result_count: int

    error_message: Optional[str] = None