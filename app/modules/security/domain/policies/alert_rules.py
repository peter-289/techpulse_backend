"""Detection rules: when does an audit event become an alert?

The rules were an ``if`` / ``elif`` chain inside ``AuditService``, which made
them untestable without a database and unlistable without reading the service.
They are pure functions here: given the event, the configured thresholds and how
much recent history matched, decide whether to raise, and build the alert if so.

Splitting selection from evaluation is deliberate. :func:`rules_for` answers
"which rules could this event possibly trigger" in a dict lookup, and it runs for
every audited request -- one per API call, including every 200. The count itself
is I/O, so the application service has to be the one to fetch it, which means
the decision has to arrive in two steps. Collapsing them would either put a
query in the domain or make the domain reach for a port.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta

from app.modules.shared.enums import AlertRuleCode, AlertSeverity, AuditEventType
from app.modules.security.domain.entities.audit_event import AuditEvent
from app.modules.security.domain.entities.security_alert import SecurityAlert
from app.modules.security.domain.ports.alert_thresholds import AlertThresholds


@dataclass(frozen=True, slots=True)
class AlertRule:
    """One detection rule: what to count, and what exceeding it means.

    Immutable and threshold-bound. :func:`rules_for` builds these from an
    :class:`AlertThresholds`, so the numbers a rule enforces are visible on the
    rule instead of being looked up out of the environment at the moment of
    comparison.

    ``template`` is the alert description, formatted with ``count``,
    ``lookback_minutes`` and ``ip_address``. Keeping it on the rule means the
    rule owns the whole of what an operator reads, and that adding a third rule
    cannot accidentally leave its phrasing behind in a service.
    """

    code: AlertRuleCode
    severity: AlertSeverity
    event_type: AuditEventType
    title: str
    threshold: int
    lookback: timedelta
    dedup: timedelta
    template: str

    @property
    def lookback_minutes(self) -> int:
        """The counting window in whole minutes, as descriptions read it."""
        return int(self.lookback.total_seconds() // 60)

    def exceeded_by(self, count: int) -> bool:
        """Whether a count of recent matching events trips this rule.

        ``>=``, not ``>``: the threshold reads as "5 or more failed logins", so
        the first alert belongs on the fifth attempt rather than the sixth.
        """
        return count >= self.threshold

    def raise_alert(self, *, event: AuditEvent, count: int) -> SecurityAlert:
        """Build the alert this rule raises for ``event``."""
        return SecurityAlert.raise_alert(
            rule_code=self.code,
            severity=self.severity,
            title=self.title,
            description=self.template.format(
                count=count,
                ip_address=event.ip_address,
                lookback_minutes=self.lookback_minutes,
            ),
            audit_event_id=event.id,
            actor_user_id=event.actor_user_id,
            ip_address=event.ip_address,
        )


_BRUTE_FORCE_BY_IP = AlertRule(
    code=AlertRuleCode.AUTH_BRUTE_FORCE_IP,
    severity=AlertSeverity.HIGH,
    event_type=AuditEventType.LOGIN_FAILED,
    title="Possible brute force login attempts",
    threshold=0,
    lookback=timedelta(0),
    dedup=timedelta(0),
    template=(
        "{count} failed login attempts "
        "from IP {ip_address} "
        "in the last {lookback_minutes} minute(s)."
    ),
)

_FORBIDDEN_REQUEST_FLOOD = AlertRule(
    code=AlertRuleCode.EXCESSIVE_FORBIDDEN_REQUESTS,
    severity=AlertSeverity.MEDIUM,
    event_type=AuditEventType.ACCESS_DENIED,
    title="Excessive forbidden requests detected",
    threshold=0,
    lookback=timedelta(0),
    dedup=timedelta(0),
    template=(
        "{count} forbidden requests detected "
        "in the last {lookback_minutes} minute(s)."
    ),
)

#: Which rule each trigger event type can raise. A lookup rather than a chain so
#: adding a rule cannot accidentally reorder the branches that select it.
#:
#: Keyed by the string value rather than by the enum member, because the event
#: types arriving from callers are plain strings. Most of them -- ``http.request``,
#: ``cookie.consent.accepted``, ``client.activity`` -- are not in
#: :class:`AuditEventType` at all, and coercing to the enum to look them up would
#: raise on the common path that raises nothing.
_RULES_BY_EVENT_TYPE: dict[str, AlertRule] = {
    AuditEventType.LOGIN_FAILED.value: _BRUTE_FORCE_BY_IP,
    AuditEventType.ACCESS_DENIED.value: _FORBIDDEN_REQUEST_FLOOD,
}


def rules_for(event: AuditEvent, thresholds: AlertThresholds) -> tuple[AlertRule, ...]:
    """Return the rules this event could trigger, possibly none.

    At most one rule applies to any event type today. This runs for every
    audited request, so it does a dict lookup and one guard and nothing else.
    """
    rule = _RULES_BY_EVENT_TYPE.get(event.event_type)
    if rule is None:
        return ()
    if rule.code is AlertRuleCode.AUTH_BRUTE_FORCE_IP and not event.ip_address:
        # Without an address the count would pool every client's failures, so
        # one attacker's attempts would raise alerts against unrelated accounts
        # and one user's typo storm would read as an attack. The rule needs an
        # address to be about anything.
        return ()
    return (_with_thresholds(rule, thresholds),)


def _with_thresholds(rule: AlertRule, thresholds: AlertThresholds) -> AlertRule:
    """Bind a rule's window and limit to this deployment's configuration.

    ``replace`` rather than mutating: the module-level rules above are the
    declarations of *what* is detected, and these are the numbers for *this*
    instance. Two services with different thresholds in one process must not
    see each other's.
    """
    threshold = (
        thresholds.login_failures
        if rule.code is AlertRuleCode.AUTH_BRUTE_FORCE_IP
        else thresholds.access_denied
    )
    return replace(
        rule,
        threshold=threshold,
        lookback=thresholds.lookback,
        dedup=thresholds.dedup,
    )
