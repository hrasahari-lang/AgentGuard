# Instructions for AI coding agents working on AgentGuard

You are implementing AgentGuard, a BYOA governance gateway. Read `PROJECT_SPEC.md`, `SYSTEM_ARCHITECTURE.md`, `SECURITY_RULES.md`, `DECISIONS.md` and `CURRENT_STATE.md` before making changes.

## Working style

- Work on only the requested milestone.
- Inspect existing files before editing them.
- Make the smallest coherent change; do not regenerate the whole project.
- Preserve working code.
- Do not install dependencies until the environment and package plan are confirmed.
- Do not invent test output or claim a command ran when it did not.
- After each change, run the narrowest relevant tests, then the broader suite when appropriate.
- If a test fails, explain the failure and fix the root cause; never delete or weaken a test merely to obtain a green result.
- Do not begin the next milestone without instruction.
- Update `CURRENT_STATE.md` with exact changes, commands, test outcomes and next action.
- Keep `PROJECT_SPEC.md`, `SYSTEM_ARCHITECTURE.md` and `DECISIONS.md` consistent if a justified decision changes.
- Keep the user informed of any package installs, network access, credential handling or destructive command.

## Security invariants

- No identity or role from MCP tool arguments.
- Authentication occurs before tool handlers.
- Protected credentials remain backend-side.
- Missing policy defaults to deny.
- The LLM never makes the final authorization decision.
- Denied and pending-approval requests do not invoke protected tools.
- Validate tool input and enforce resource scope in the actual resource operation.
- Separate policy decision from execution outcome.
- Redact secrets and sensitive values in audit logs.
- Fail closed if authorization cannot be established.

## MCP version discipline

The official MCP Python SDK v2 was the current stable line on 2026-11-05. Verify the current release and read its v2 docs before implementing. Do not copy v1 `FastMCP` / SSE tutorials without checking the migration guide. Prefer Streamable HTTP for deployed integrations.

## Token/quota efficiency

- Use concise task prompts and focused file scopes.
- Read project docs once and refer to them rather than repeatedly summarizing the entire product.
- Avoid full-repository re-analysis unless necessary.
- Ask the user before switching models or consuming large tool workflows.

# HACKATHON MASTER GOAL & FINAL DELIVERY

## Primary Objective
Build AgentGuard into a fully functional, professionally designed and publicly deployed BYOA AI Agent Governance Platform for iQOO Hackathon 2026.

The objective is to build a competitive hackathon submission, not merely a prototype dashboard.

## Mandatory Product Requirements

1. Connect existing compatible AI agents through MCP and supported integrations.
2. Authenticate agents using verified identities.
3. Implement RBAC and resource-level authorization.
4. Implement deterministic risk and policy evaluation.
5. Support ALLOW, REQUIRE_APPROVAL and DENY.
6. Enforce protected tool execution server-side.
7. Implement human approval with replay protection.
8. Maintain persistent, auditable security events.
9. Prove blocked requests never reach protected resources.
10. Build a professional enterprise-grade React + TypeScript interface.
11. Connect every dashboard feature to real backend functionality.
12. Never display fabricated metrics or simulated events as real.

## Mandatory Development Workflow

After EVERY milestone:

- Report completed, pending and blocked tasks.
- Run relevant automated tests.
- Verify actual test results.
- Review security and architecture.
- Update CURRENT_STATE.md.
- Update GOALS_AND_PROGRESS.md.
- Record important decisions in DECISIONS.md.
- Commit verified working changes to Git.
- Identify the exact next task.

Never mark a feature complete without implementation and test evidence.

Never overwrite working code unnecessarily.

## Mandatory Deployment Goal

The project is NOT complete until successfully deployed.

Final deployment requirements:

- React frontend hosted on Render Static Sites.
- FastAPI backend and MCP gateway hosted on Render Web Services.
- Persistent production database, preferably Render PostgreSQL.
- Secure environment variable configuration.
- HTTPS and correct CORS configuration.
- Working frontend-to-backend integration.
- Working remote MCP endpoint.
- End-to-end testing against the deployed application.
- Public project URL.
- GitHub repository.
- Final demonstration video.

## Hackathon Prize Strategy

The Best Use of Render prize track requires genuine Render Workflows usage.

If pursuing this track:

- Integrate actual Render Workflows.
- Use workflows for meaningful AgentGuard operations.
- Demonstrate real workflow execution.
- Do not substitute ordinary deployment or simulated workflows.

Explore meaningful ElevenLabs integration separately without compromising the core security architecture.

## Progress Management

Maintain GOALS_AND_PROGRESS.md as the master milestone tracker.

Calculate progress using verified acceptance criteria, not lines of code or generated files.

Keep portable documentation updated so another coding agent can continue development if Antigravity reaches its usage limit.

## Final Definition of Done

AgentGuard is complete only when:

1. Existing compatible AI agents can connect.
2. Protected tool calls are genuinely governed.
3. Unauthorized operations are prevented.
4. Human approvals work correctly.
5. Audit records persist.
6. The professional frontend works with the real backend.
7. Automated security tests pass.
8. The application is publicly deployed.
9. The complete demonstration can be reproduced.

Preserve the original BYOA vision throughout development.
Prioritize real functionality, security, usability and hackathon competitiveness over unnecessary feature breadth.