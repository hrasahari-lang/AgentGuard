# AgentGuard — portable project starter pack

This folder is the source of truth for the AgentGuard hackathon project. It is designed to be opened in Google Antigravity, Codex, or another coding agent. It also contains the original project materials so the work can be moved to another AI tool if a quota runs out.

## Important: preserve the workspace path

Your Antigravity file permissions currently allow reads and writes only under:

`C:\Users\nunna\Desktop\GURDAI1`

Keep using that folder for this project. Do not rename it unless you update Antigravity's file rules too.

## Included files

- `PROJECT_SPEC.md` — product scope and acceptance criteria.
- `SYSTEM_ARCHITECTURE.md` — control plane, enforcement plane and request flow.
- `SECURITY_RULES.md` — security invariants and known limitations.
- `IMPLEMENTATION_ROADMAP.md` — ordered build plan with proof requirements.
- `CURRENT_STATE.md` — current progress and next task.
- `DECISIONS.md` — decisions that should not be casually reopened.
- `AGENTS.md` — standing instructions for coding agents.
- `ANTIGRAVITY_FIRST_PROMPT.md` — first prompt to use after opening this folder.
- `HANDOFF_TO_OTHER_AI.md` — instructions for transferring the project to another AI.
- `REFERENCE_LINKS.md` — official technical documentation links checked on 2026-11-05.
- `source_material/` — original deck, technical framework PDF and independent AI review.

## Start here

1. Extract this folder into `C:\Users\nunna\Desktop\GURDAI1` (or copy its contents into that existing folder).
2. In Antigravity, open `C:\Users\nunna\Desktop\GURDAI1` as the workspace.
3. Read `AGENTS.md` and `CURRENT_STATE.md`.
4. Paste the contents of `ANTIGRAVITY_FIRST_PROMPT.md` into Antigravity.
5. The first task is environment inspection and a plan review only. Do not install packages or generate the whole app yet.

## If the coding agent runs out of quota

1. Keep all files in this folder. The source of truth is the files, not the chat transcript.
2. Update `CURRENT_STATE.md` after each milestone with completed work, exact test results, current errors and the next command/task.
3. Commit working code to Git after each passing milestone.
4. Give the next AI `HANDOFF_TO_OTHER_AI.md`, `CURRENT_STATE.md`, and this folder. Include the source PDFs if the new AI needs the original pitch details.
5. Never paste secrets, API keys, database passwords or private customer data into these documents.

## Status

This is a project handoff and planning pack, not a finished or production-secure application. The implementation has not yet been run on your Windows machine. Python, Node.js, npm, Git and package availability must be checked in the actual workspace before implementation.
