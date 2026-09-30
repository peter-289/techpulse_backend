# ADR 0008 — Support chat gets a port, and the blocking call goes away with it

- Status: accepted
- Date: 2026-09-30
- Refactor phase: 6a

## Context

`SupportChatService` was 121 lines and held four unrelated things:

```python
SYSTEM_PROMPT = "You are Tech Pulse customer support. ..."   # policy
if len(cleaned) < 2: raise ValidationError(...)              # policy
if not settings.AI_API_KEY: return self._fallback_reply()    # configuration
response = requests.post(url, headers=headers, json=payload, timeout=60)  # transport
```

It was the only application service in the codebase making a network call, and it
held four ratchet entries: R4 for `app.core.config`, R4 and R5 for the
`ChatMessage` ORM model, and R8 for `requests`.

The R8 entry was pointing at something worse than a layering violation.
`requests.post` performs blocking I/O on the calling thread. The call sat inside
a coroutine on the event loop, with a 60-second timeout, so a slow or hanging
provider would occupy the worker thread and stall every other in-flight request
for up to a minute. Layer rules found the import; the scheduler found nothing.

## Decision

### 1. A `SupportAI` port, and the call became `async`

```python
class SupportAI(Protocol):
    async def generate_reply(self, question: str, system_prompt: str) -> str: ...
```

`HttpSupportAI` implements it in `app/infrastructure/external_apis/ai_support/`
using `httpx.AsyncClient`. `httpx==0.28.1` was already a pinned dependency and
was used nowhere, so this adds no new package. It fixes the blocking, and it
forced the response parsing to be pinned by tests rather than assumed.

### 2. The system prompt travels per call, not in the config

The natural first cut put `system_prompt` in `SupportAIConfig` and had the
composition root import it from the domain. R2 rejected that: the composition root
may read another context's `domain.ports` and nothing else, and the prompt
belongs in `domain.policies.support_chat_policy` because it states what the
support bot is allowed to tell a customer.

Rather than widen R2 or move the prompt into infrastructure, the port takes it as
an argument. The prompt stays with the policy, the service supplies it, and the
config carries only what is genuinely deployment configuration: base URL, API
key, model, timeout.

**Rejected: widen `_is_port` to admit `domain.policies`.** It would let any
composition-root-adjacent code reach any context's policy layer, which is the
thing R2 exists to prevent.

**Rejected: move the prompt into the adapter.** Infrastructure is the worst home
for a statement about what support may say to a customer.

### 3. Every failure mode collapses to one signal

The old service had four distinct `ExternalServiceError` messages for connection
failure, HTTP error, non-JSON body and empty completion, and it caught all four to
substitute a canned reply. The adapter now raises a single
`SupportAIUnavailableError` for all of them, and the service catches that one.

The distinction was never used: every path produced the same user-visible result.
Collapsing it means the service has one decision to get right, and the specific
cause survives in the log line.

### 4. The too-short rule is a domain policy, and runs before the model is called

`clean_question` trims and length-checks, raising `ChatMessageTooShortError`
(the 422 the shared-kernel `ValidationError` produced).

Its position matters and is the reason it is a separate function rather than a
check inside `ChatMessage.create`. Building the entity after the model call would
be the natural order, which would mean a one-character submission costs a full
round trip before being rejected. `test_a_short_question_never_reaches_the_model`
pins the ordering.

### 5. `list_messages` no longer commits

It opened a write transaction for a pure read. It now uses `read_only()`, matching
`user_service.list_users` and the shared Unit of Work's stated contract. No
response changes; a read that commits can mask a missing commit elsewhere in the
same request.

## Consequences

**Good**

- All four `support_chat_service` ratchet entries are gone; the ratchet is 10.
- The event loop is no longer blocked for up to 60s per support-chat request.
  `test_concurrent_questions_do_not_serialize` is the regression test, and it
  was mutation-checked: reverting the adapter to a synchronous call makes it fail.
- 42 new tests, 308 passing.
- Degraded mode is directly testable. The fallback path previously required
  either no API key or a real endpoint to exercise.

**Bad**

- The service now takes a second constructor argument. Every caller must supply a
  `SupportAI`; a missing one is an `AttributeError` at the first question.
- `SupportAIUnavailableError` is deliberately *not* a `UserDomainError`, so it
  would be a 503 if it ever escaped. It is registered anyway, for parity with the
  `ExternalServiceError` it replaced, but the handler is currently unreachable.

**Neutral**

- The response parser moved verbatim, including its tolerance for three
  different provider shapes. Behaviour is unchanged and now tested.

## Not done, and why

The `User` aggregate is **not** in this phase. Phase 6a clears the four
`support_chat_service` entries; the four `user_service` entries remain for 6b.

`users` is not a bounded context in this codebase. `user_repo` is reached by
`auth_service`, `verification_recovery` and `superuser_seeder`, and the first two
mutate rows it hands them and depend on session autoflush:

| Site | Mutation | If the repository returned detached entities |
|---|---|---|
| `auth_service.py:98` | `user.password_hash = verified_hash` | rehash-on-login silently stops happening |
| `auth_service.py:123` | `user_acc.status = VERIFIED` | accounts never verify — total lockout |
| `auth_service.py:218` | `user.password_hash = ...` | reset reports success, old password keeps working |
| `verification_recovery.py:45-48, 76-78` | 4 retry-bookkeeping fields | unbounded verification-email retry loop |

Every one of those fails *silently*: the request returns 200/201 and the write
does not happen. There is no test that would catch it — `test_auth_hardening.py`
drives `AuthService` with fake repositories and never touches a real
`UserRepo` write path.

Phase 6b therefore starts with integration tests over a real database for those
four flows, and only then converts. The alternative — adding explicit
`update_status` / `update_password_hash` save operations and rewriting seven
mutation sites in the authentication context — was considered and left for
Phase 7, which owns `auth_service` anyway.

`UserUnitOfWork.user_repo` and `session_repo` are therefore still annotated
`object`, and their docstrings now say why and point at Phase 6b.
