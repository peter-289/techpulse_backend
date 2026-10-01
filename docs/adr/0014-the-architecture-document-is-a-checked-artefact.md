# ADR 0014: The reference architecture document is a checked artefact

- **Status:** Accepted
- **Date:** 2026-10-01
- **Deciders:** backend maintainers
- **Supersedes:** nothing
- **Related:** ADR 0001 (module per bounded context), ADR 0004 (layer boundaries and the ratchet)

## Context

`app/modules/software_management/ARCHITECTURE.md` is the document a reviewer reads
to decide whether a change to this context is placed correctly. Between the last
substantive edit and Phase 9a it had drifted from the code in roughly forty places
across nineteen sections. Not cosmetic drift:

- a directory tree (`software/software.py`, `category/application/category_service.py`)
  that had not existed since Phase 1;
- port names that collided with the concrete classes they described, so three
  different things in the context appeared to be called "Category repository";
- a `Storage` port with a `create_download_url` method it has never had;
- two event classes, `SoftwareCreated` and `ArtifactUploaded`, that have never
  existed;
- a quality gate requiring `mypy --strict`, in a project where mypy is not
  installed, has no config file and is not in `requirements.txt`;
- a section describing the search implementation as future work, years after it
  shipped.

Phase 1 recorded the first four divergences and wrote that the document should be
corrected "against something real in Phase 9a". Nine phases later the count was
roughly ten times that.

The reason it drifted is worth stating precisely, because it decides the decision.
**Nothing in the workflow distinguished a sentence that was still true from one
that was not.** The document was reviewed by people reading it for context, and
readers cannot check forty claims per pass — a plausible sentence reads exactly
like a true one. Two of its fabrications were of the kind that survive review
especially well: a `console` block showing output that was never run, and a count
of exception classes that was written from memory.

A codebase-wide audit reported the port-defaulting defect (ADR 0013) as clean
because it walked packages rather than the filesystem. This is the same failure
one level up: a check that cannot see the code passes.

## Decision

1. **`ARCHITECTURE.md` describes the code as it is, not as it was planned.** Every
   claim is about the present. Anything that does not exist yet lives in a section
   explicitly marked *(not implemented)*.
2. **Where a sentence used to say what the previous version claimed, the new
   sentence says so.** The document now records its own corrections, because a
   reader who finds a contradiction in it should be able to check whether it is a
   stale claim or a stale correction.
3. **`tests/architecture/test_architecture_doc_matches_code.py` enforces the
   checkable claims**, and the document states in section 1 which claims those are.
   The checks are:
   - the section 2 tree, compared with the filesystem in both directions, by
     parsing the fenced block — so a new file and a moved file both fail;
   - every `app/`, `tests/` or `docs/` path named in backticks must exist;
   - every name marked *(not implemented)* must still be absent from `app/`;
   - the counts the document quotes — routes per router and their prefixes, event
     classes, exception classes, the size of the `Clock` port;
   - the ratchet's `violations` list is still empty, and the eight layer rules are
     still the eight it names;
   - `matched_fields` is still absent from the search route, and the response keys
     it lists are still returned;
   - the test gaps section 18 records are still gaps.
4. **The guard walks the filesystem and never imports the application.** Checking a
   document about the code must not require an environment the code needs.

## Rationale

**Why a test rather than a review checklist.** A checklist is read once by the
person who writes the document, which is the person least able to see its own
assumptions. A test runs on every change, including the ones nobody thought were
documentation-relevant — which is exactly when a tree entry goes stale.

**Why absence is checked as well as existence.** A document that describes a target
architecture has no way to fail when the target arrives; the section keeps calling
something future work and nobody notices it is shipping. The *(not implemented)*
markers turn "we meant to do this" into something that breaks on completion.

**Why the tree is parsed rather than compared against a generated listing.** The
comments in the tree are the useful part — they say what each file is *for*. A
generated listing would be accurate and worthless, which is the failure mode this
ADR exists to prevent.

**Why no markup inside the prose.** Machine-readable markers beside each claim were
rejected: two statements of the same fact drift apart, and the marker would be the
one nobody updates. The claims are read out of the sentences themselves, so a
rewrite that changes the meaning of a sentence fails the check rather than silently
disabling it.

**Why the guard does not try to check the arguments.** It checks facts. A document
that stops arguing is a worse document, and no gate should be the reason to delete
an argument. Prose claims that cannot be found by reading the file — "the port is
four methods", for instance — are explicitly outside what this ADR promises.

**Rejected: delete the document.** A wrong architecture document is a hazard; no
architecture document is a hazard of a different kind, in which placement decisions
are made from the import graph by reading it, which is slower and no more accurate
for anything requiring judgement.

**Rejected: rewrite it as the target architecture.** That is what the previous
version tried to be, and the failure mode is specific: a target document has no
relationship to the code, so nothing about it can ever be verified, and a reviewer
cannot tell which of its statements are aspirations without reading all of it.

## Consequences

**Good**

- A moved, added or renamed file in this context fails CI until the document says
  something about it.
- A fabricated count, a nonexistent path, or a "not implemented" name that shipped
  is a test failure with the real number or the real class in the message.
- The corrections the phase made are themselves checkable, so the next reader can
  verify the rewrite rather than trust it.

**Bad**

- Churn. Adding a file to the context requires editing this document in the same
  commit, and the route counts and class counts must be refreshed when they change.
  That is the intended cost, but it is a cost, and a team that resents it will find
  ways to make the document worse.
- Two of the three fabrications this ADR was written about — the console transcript
  and the exception count — were in documents reviewed across nine phases. A guard
  added now does not make anyone trust the parts it cannot check; the sections it
  does not cover are still exactly as trustworthy as they were before, which is to
  say: not at all until someone reads them against the code.
- The guard can be satisfied by a document that is technically accurate and
  useless. It checks that claims are true, not that they are the right claims.

**Neutral**

- The document is scoped to one context. `authentication`, `security`, `resource`
  and `user` have no equivalent, and adding one is mechanical rather than
  interesting.