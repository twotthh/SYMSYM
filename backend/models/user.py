from dataclasses import dataclass
from datetime import datetime

@dataclass
class User:
    email: str
    target_domain: str
    created_at: datetime
    last_scan: datetime
    scan_cycle: str
    is_active: bool