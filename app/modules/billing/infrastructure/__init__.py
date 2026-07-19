"""Billing bounded-context infrastructure.

This package contains adapters and integration code for external systems: the
SQLAlchemy repositories, the payment provider gateways, webhook handling, and
the dependency container. It depends on every other layer; no other layer
depends on it.
"""

