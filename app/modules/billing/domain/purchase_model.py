# Backwards-compatible re-export. The canonical Purchase aggregate now lives in
# ``app.modules.billing.domain.purchase``.
from app.modules.billing.domain.purchase import Purchase

__all__ = ["Purchase"]
