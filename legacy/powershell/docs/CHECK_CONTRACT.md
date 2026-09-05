# Provider check contract

Claudit separates each provider check into three small steps:

1. collect read-only provider data;
2. evaluate that data with a pure analyzer;
3. convert one `Claudit.CheckAssessment` into the normal finding model.

`New-CaCheckAssessment` supports four unambiguous policy-check states:

- `Pass`: the resource was evaluated and is compliant;
- `Fail`: the resource was evaluated and is non-compliant;
- `NotApplicable`: the provider was queried successfully but no applicable
  resource exists, or the baseline explicitly excludes the control;
- `Error`: the control could not be evaluated. It requires a non-Info severity
  and an explicit failure category.

`Warning`, `Investigate`, `Info` and `Skipped` remain available through
`New-CaFinding` for advisory, manual-review and orchestration results. They are
intentionally outside the strict provider policy contract.

Unlike Prowler's zero-result convention for no resources, Claudit emits an
explicit `NotApplicable` finding. This preserves auditable completeness and
proves that the provider query succeeded.

The AWS VPC Flow Logs check is the reference implementation:

- `Get-CaAwsVpcFlowLogSnapshot` owns CLI collection;
- `Test-CaAwsVpcFlowLogSnapshot` is deterministic and network-free;
- `Test-CaAwsVpcFlowLogs` only orchestrates and converts the assessment.

Offline fixtures live under `tests/fixtures/providers/`. Fixtures contain no
credentials, tenant identifiers or captured secrets.
