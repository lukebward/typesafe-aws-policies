# typesafe-aws-policies

- [x] Scaffold repo, venv, deps
- [x] judge.py (TypeSafe wrapper) with tests
- [x] policies.py: 15 validators with tests
- [x] __main__.py wiring
- [x] examples/demo stack, offline preview
- [x] README
- [ ] Private GitHub repo, push
- [x] Rewrite: code decides exact cases, model gets the gray zone (15 policies)
- [x] Live run with TYPESAFE_API_KEY (44/44 live cases, demo preview 18 mandatory + 11 advisory violations, all intended)

## Review
- Live run 2026-09-17: 44/44 live cases pass. Demo preview: 29 violations, all intended, zero on the compliant resources.
- Three original misses were all IAM chain reasoning over raw JSON (0.52 to 0.59). Fix was not a threshold change: code now extracts
  the relevant facts (catalog-matched actions, principal kind, condition keys) and decides the known cases itself; the model only
  gets the residue (unlisted service wildcards with PassRole, federated subject breadth). Residue cases score 0.85 to 0.98.
- False positive found and fixed: 'ci-scratch' read as test environment vs dev tag. dev and test now share one class.
- Cosmetics fixed: float ports rendered as 22.0, Pulumi auto-name suffixes leaking into messages and model state.
- Follow-ups: batch all questions for one resource into one request; stack-level policy for the separate S3 configuration resources.
