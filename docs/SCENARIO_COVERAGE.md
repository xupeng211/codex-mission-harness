# Scenario 1–8 coverage

The test count and scenario count deliberately differ: two tests each verify two related product scenarios, while the App Server test is an additional protocol regression.

| Scenario | Acceptance behavior | Test evidence |
| --- | --- | --- |
| 1: Background verify | One registered verify process is polled and never duplicated after a turn ends. | `test_background_verify_continues_same_mission_without_duplicate` |
| 2: Docker collision | Namespace is mission-unique and no existing resource is deleted. | `test_docker_namespace_is_unique_and_non_destructive` |
| 3: HEAD after review | Both reviewers' A receipts are invalidated on B. | `test_head_change_invalidates_both_reviews` |
| 4: Review P1 | A failed review returns to implementation rather than blocking the mission. | `test_review_p1_and_ci_fail_are_repaired_not_blocked` |
| 5: CI failure | A failed CI result returns to implementation and then continues. | `test_review_p1_and_ci_fail_are_repaired_not_blocked` |
| 6: Harness restart | Persisted process/gate state is reconciled and resumed without replay from CREATED. | `test_restart_resume_reconciles_not_restart_zero` |
| 7: Agent says incomplete | Natural-language text cannot terminate a mission. | `test_agent_prose_is_not_terminal_and_invalid_transition_fails_closed` |
| 8: Agent says done early | A prohibited direct transition to PASS fails closed. | `test_agent_prose_is_not_terminal_and_invalid_transition_fails_closed` |

Additional protocol coverage: `test_app_server_turn_requires_completed_notification` proves that accepting `turn/start` is not treated as completion; the adapter waits for matching `turn/completed`.

All scenarios are deterministic fixtures: no live provider, DNS probe, production authorization, FootballPrediction Stage D action, or external CI credential is used.
