from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class User:
    email: str
    target_domain: Optional[str] = None
    created_at: Optional[datetime] = None
    last_scan: Optional[datetime] = None
    scan_cycle: Optional[str] = None
    is_active: bool = True