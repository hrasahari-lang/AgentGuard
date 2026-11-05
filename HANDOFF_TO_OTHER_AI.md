# AgentGuard — Handoff to another AI / coding agent

You are taking over an existing hackathon project. Do not restart discovery from scratch.

## Read first

1. `AGENTS.md`
2. `CURRENT_STATE.md`
3. `PROJECT_SPEC.md`
4. `SYSTEM_ARCHITECTURE.md`
5. `SECURITY_RULES.md`
6. `DECISIONS.md`
7. `IMPLEMENTATION_ROADMAP.md`
8. `source_material/` for the original deck, technical framework and independent review.

## What the project is

AgentGuard is a Bring Your Own AI Agent governance gateway. Users connect existing compatible agents. The MVP governs protected tool calls routed through an MCP Streamable HTTP gateway. It authenticates agents, evaluates server-side permissions and deterministic risk policies, controls execution and records audit events.

It is not an agent builder and it does not automatically control arbitrary software or all actions of an agent just because a model API key is supplied.

## What has already been decided

- MCP Streamable HTTP first.
- One external agent first; second framework is a stretch test.
- Agent identity comes from verified transport credentials, never tool arguments.
- Backend alone holds protected resource credentials.
- Missing/unknown policy denies.
- Decision and execution outcome are separate.
- Denied and approval-pending calls never reach the protected CRM.
- Invocation counter measures actual protected resource calls.
- No dashboard before a real enforcement path exists.
- No production or universal-interception claims beyond tested boundaries.

## What has already been reviewed

The original pitch deck and technical framework PDF are included under `source_material/`. An independent AI review is also included. Critical issues in the sample implementation were identified: caller-supplied `agent_id` could enable impersonation, the sample did not validate a token, invocation counter logic was missing, audit failure handling was weak, resource scope was not enforced in the SQL query, and approval was only a returned string.

## Current status

Read `CURRENT_STATE.md` for the live state. Do not assume code or tests exist unless the file says so and the files confirm it.

## Your first action

Inspect the current workspace and report exact environment/dependency status. Then implement only the next incomplete milestone from `IMPLEMENTATION_ROADMAP.md`.

## Expected work report after each milestone

- Summary of behavior implemented.
- Exact files changed.
- Commands run.
- Actual test output and pass/fail counts.
- Known limitations or security concerns.
- Updated `CURRENT_STATE.md`.
- Suggested next milestone.

Do not ask the user to restate the idea. Do not rebuild the project from zero. Do not claim all agents are supported.
