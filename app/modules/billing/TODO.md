# PaymentRepository implementation - TODO

- [ ] Inspect existing billing persistence/mapping utilities (current repo has none; implement within repository if required by task constraints)
- [x] Implement `PaymentRepository` fully: `save`, `get`, `find_by_provider_reference`, `exists_pending`, `list_for_buyer`
- [x] Add comprehensive docstrings, logging, and production error handling (`SQLAlchemyError` -> `RepositoryUnavailableError`)


- [x] Ensure SQLAlchemy async 2.0 patterns: `select`, `scalar`, `scalars`, `exists`, `merge`, `flush`, `refresh`

- [x] Ensure performance: projection list query + separate count; EXISTS query for pending existence

- [ ] Add comprehensive docstrings, logging, and production error handling (`SQLAlchemyError` -> `RepositoryUnavailableError`)
- [ ] Ensure type-safety and correct SQLAlchemy model field mappings
- [ ] Run backend tests / basic import check

