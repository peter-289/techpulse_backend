# Backwards-compatible re-export. The canonical Payment aggregate now lives in
# ``app.modules.billing.domain.payment``.
from app.modules.billing.domain.payment import Payment

__all__ = ["Payment"]
