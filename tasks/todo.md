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
- Real-stack run (pulumi/pulumi-service-review-stacks/lward-local): first pass blocked on same-account root trust and showed
  'can't run during preview' for a computed IAM policy. Fixed with ownAccountId/trustedAccountIds config, an advisory
  iam-trust-account-wide policy, not-applicable on unknown documents, aws-native role support, and audit.py for full verdicts.
- Refactor 2026-09-17: @policy decorator (registry, type guard, applicability in one place), judge.noul_each for fan-out,
  Q_* question constants above each policy, classify_trust shared by both trust policies. 725 -> 694 lines, longest function 25 lines.
- Follow-ups: batch all questions for one resource into one request; stack-level policy for the separate S3 configuration resources.
