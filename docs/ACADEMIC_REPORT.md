# Nexus technical project report

## Problem and objective

Operational information often spans separate supply-chain and IT systems. Nexus studies how typed
shared context, explainable risk rules, specialist analysis and human approval can support a
traceable operational response. The academic objective is a reproducible prototype with measurable
behavior across controlled scenarios.

## Implemented architecture

The shared Python engine builds a typed projection, calculates two domain risk signals, runs
supply and IT specialist functions concurrently, records a cross-domain critic finding and obtains
bounded advisory text. It prepares an immutable R3 simulated action. A separate person approves
the exact plan hash before the proposer can execute it. Verification records the simulated result.

Two applications exercise the engine:

- The academic launcher uses FastAPI, SQLite and explicit local demonstration roles. Transactions
  persist snapshots, command receipts and hash-linked audit events. Reads check both event-chain
  integrity and whether the saved snapshot follows from those events. The UI uses returned data.
- The full governed application retains Keycloak/OIDC identities, tenant scopes, OPA authorization,
  PostgreSQL persistence, strict audit replay and exact-plan preconditions. Its live dependencies
  remain a separately tested deployment path rather than a prerequisite for the academic demo.

The original historical graph and plan remain replay-compatible. New scenario projections contain
numeric input evidence. Their seed digest and plan hash bind the selected versioned inputs.

## Data and analytical methods

Four synthetic scenarios vary baseline shipment delay, affected shipment count and checkout latency.
The graph includes ports, shipments, a component, purchase orders, deployments, services and a
database. New scenario input nodes identify the numerical evidence used by the calculations.

The supply risk index is `min(1, round(0.10 + 0.02 × delay_hours + affected_shipments / 12, 2))`.
The implementation uses a fixed decimal approximation to `1/12`. The IT index is
`min(1, round(0.30 + 0.16 × latency_shift_minutes, 2))`. Both use a high-risk threshold of `0.80`.
These explainable demonstration indices are neither calibrated probabilities nor trained forecasts.

Each specialist chooses a threshold-based finding and cites the graph evidence. The critic records
whether both domains exceed their thresholds. It labels temporal association as uncertainty and
does not claim that a software deployment caused a port disruption.

The simulator compares no action with rerouting. The declared reroute assumption reduces baseline
delay by 50%. Final delay equals baseline minus reduction. This calculation demonstrates scenario
comparison and approval binding. It does not establish carrier capacity, cost optimality or real-world
logistics improvement. A reviewer can reject the plan and retain no action.

## AI and evidence boundaries

The OpenAI-compatible adapter requests schema-constrained output over allowlisted evidence. It
validates citations and bounds input/output size. The application screens displayed text and records
its digest and citations. Provider failure produces a fact-only explanation. LLM advice cannot alter
scores, policy, immutable plan parameters, approvals or execution state.

The specialist functions are deterministic agents with distinct domain responsibilities and concurrent
coordination. This project does not claim online learning or an unrestricted autonomous agent system.

## Evaluation

[The generated evaluation](EVALUATION.md) reports actual repeated HTTP workflows, independent
expected scores, citation checks, separate-role approval, stale-plan rejection, calculated outcomes,
audit history and restart persistence. The tests also cover snapshot tampering, event tampering,
idempotency conflicts, terminal rejection, invalid roles and stale browser responses.

The browser acceptance flow runs two scenarios through proposer, approver, execution and trace
inspection at desktop and mobile widths. Results establish controlled prototype correctness.
Latency measurements are in-process HTTP and SQLite timings and exclude external network/model
latency. Four synthetic cases cannot establish performance on unseen operational incidents.

## Research foundations

These sources motivate design choices; Nexus does not claim to implement their complete frameworks:

1. Hogan et al., *Knowledge Graphs*, ACM Computing Surveys, 2021.
   https://arxiv.org/abs/2003.02320
2. Yao et al., *ReAct: Synergizing Reasoning and Acting in Language Models*, ICLR, 2023.
   https://arxiv.org/abs/2210.03629
3. Wu et al., *AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation*, COLM, 2024.
   https://arxiv.org/abs/2308.08155
4. Lewis et al., *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*, NeurIPS, 2020.
   https://arxiv.org/abs/2005.11401
5. Amershi et al., *Guidelines for Human-AI Interaction*, CHI, 2019.
   https://www.microsoft.com/en-us/research/publication/guidelines-for-human-ai-interaction/

## Outcome and extensions

The deliverable connects scenario evidence to analysis, readable advice and a persisted,
human-approved simulated response. It includes a local launch command, tests, a browser workflow,
an evaluation runner and documentation. Future research can add real datasets, calibrated models,
more realistic simulation assumptions and additional domains. Those extensions are outside the
completed controlled academic scope.
