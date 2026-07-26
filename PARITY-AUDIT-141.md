<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Task #141 — PoC ↔ fleet parity audit (tool surface)

Read-only. PoC = `/Users/nick/open-computer-use` @ `docs/demo-walkthrough`. Fleet =
`ocu-mcp-gateway` (this repo) + `ocu-control` + `ocu-webui` + `deploy/fleet`. Every
row is firsthand-read (file:line cited). Nothing was edited; the stand was not touched.

Verdict legend: **parity** (present + equivalent) · **GAP** (missing / diverges, may
need action) · **by-design** (deliberate fleet split/change, canon-cited) · **known**
(already tracked — not re-derived per dispatch).

---

## A. MCP tool surface (the tool-call ingress — my domain)

| feature | PoC (file:line) | fleet (file:line) | verdict |
|---|---|---|---|
| `bash_tool` | mcp_tools.py:473-537 | tools_list.json (advertised) + projection.go `Project` (`/bin/sh -c`) | **parity** |
| `str_replace` | mcp_tools.py:540-614 (3 error semantics) | tools_list.json + projection.go `StrReplaceScript` (same 3 semantics) | **parity** |
| `create_file` | mcp_tools.py:617-674 | tools_list.json + projection.go `CreateFileScript` | **parity** |
| `view` — text/dir | mcp_tools.py:677-812 | tools_list.json + projection.go `ViewScript` (numbered / dir / not-found) | **parity** |
| `view` — **image resize** (PIL thumbnail→JPEG, returns image content block) | mcp_tools.py:741-763 | **absent** — ViewScript handles text/dir only; a binary body renders via `errors='replace'`, no image resize | **GAP** (image-view path not ported; declared out-of-scope in #40/#42 CONSTITUTION §III, so **by-design for MVP** but worth a canon line) |
| `view` — **binary-hint table** (.xlsx/.docx/.pdf → "read SKILL.md") | mcp_tools.py:722-732 | absent | **GAP** (skill-hint UX not ported; low priority) |
| `sub_agent` (spawn claude/codex CLI subtask) | mcp_tools.py:939+ (`SUB_AGENT_MAX_TURNS=25`, `SUB_AGENT_TIMEOUT=3600`) | **delisted** from tools_list.json | **by-design** (MANIFESTO v1 non-goal — OCU does not run the agent loop; CONSTITUTION §I) |
| `describe-image` / Vision API skill | docker_manager.py:176-179, 582-585 (`VISION_API_KEY/URL/MODEL=gpt-4o`) | no fleet vision wiring | **GAP** (Vision-backed skills — describe-image, upd-processing — have no fleet analog; skill-runtime scope, likely by-design but uncited) |
| tool arguments carried opaque to guest | (direct kwargs) | forward `ToolCall.Stdin` opaque, injection-safe (invariant #3) | **parity** (fleet stronger — args ride stdin, never interpolated) |
| exit→content shaping (`[Exit code: N]`) | mcp_tools.py:456 | http.go `projectCallToolResult` (#127) | **parity** |
| non-`bash` unimplemented tool | — | well-formed `-32602`, no hang (#37) | **by-design** (fleet-only correctness fix) |

---

## B. Path map / mount destinations

| feature | PoC (file:line) | fleet (file:line) | verdict |
|---|---|---|---|
| writable work home | docker_manager.py:629 `working_dir=/home/assistant` | control docker.go:742 tmpfs `/home/assistant rw,exec 512m` (#133) | **parity** (proven live by dev-lead) |
| user uploads (RO) | docker_manager.py:651 `/mnt/user-data/uploads` (ro) | F7 mount-config push (storage-scoped) | **known** (chat-attachment upload leg = #140, in progress (webui peer)) |
| outputs (downloadable) | docker_manager.py:652 `/mnt/user-data/outputs` (rw) | guest sees FLAT `/mnt/user-data`; outputs/ join on storage engine | **by-design** (ADR-0029; dev-lead firsthand-confirmed guest view flat, `/outputs` subdir → ENOENT) |
| `/tmp` scratch | (implicit) | control docker.go:741 tmpfs `/tmp rw,noexec 64m` | **parity** |
| tool-description path steering | system_prompt.py path map | tools_list.json (enriched #135, merged @9aa6dc4) | **parity** (fleet now steers the model to writable paths) |
| provisioning `mount_intent.destination` vs guest storage mount `/mnt/user-data` | — | tracked fixture provisioning-policy.json `destination:/mnt/user-data` (@e01b29d); gateway session.go:246 projects into create-body; control renders as-is | **parity — CLOSED** (the `/workspace` I first read was a FALSE POSITIVE from the dev-lead's stale untracked host secrets-copy; the live stand + tracked fixture always held `/mnt/user-data`, field live end-to-end, control chain verified firsthand by the control peer) |

---

## C. Lifecycle / limits / TTL

| feature | PoC (file:line) | fleet (file:line) | verdict |
|---|---|---|---|
| guest memory | docker_manager.py:42 `CONTAINER_MEM_LIMIT=2g` | provisioning-policy.json `memory_bytes=2147483648` (2 GiB) | **parity** |
| guest CPU | docker_manager.py:43 `CONTAINER_CPU_LIMIT=1.0` | provisioning-policy.json `cpu_cores=2` | **GAP** (minor: fleet gives 2 cores vs PoC 1.0 — a cap, not a floor; likely intentional headroom, uncited) |
| pids limit | (none in PoC) | provisioning-policy.json `pids_limit=512` | **by-design** (fleet-only DoS guard) |
| command / exec timeout | docker_manager.py:44 `COMMAND_TIMEOUT=120` | gateway ExecTimeoutSeconds clamp [1,300] (#29); policy fixture now sets `exec_timeout_seconds=120` (was inheriting the 30 default) | **parity — CLOSED** (was a real GAP: fleet inherited the 30 s default vs PoC 120 s; fixed by setting `exec_timeout_seconds=120` in the fixture + stand; `sleep 45` went red→green live) |
| idle-kill / session reaper | docker_manager.py:62 `CONTAINER_IDLE_TIMEOUT=600` (10 min) | control `-session-idle-ttl ${OCU_SESSION_IDLE_TTL:-15m}`, NFR-SEC-40 ≤15 min ceiling (compose:614-623) | **by-design** (PoC 10 min vs fleet 15 min ceiling — the fleet comment explains a 1 m window wiped work mid-conversation; the 15 m default sits at the NFR-SEC-40 ceiling. Divergence is deliberate and canon-cited; dev-lead already flagged this as expected) |
| sub_agent turn/time caps | docker_manager.py:79-80 (25 turns / 3600 s) | n/a (sub_agent delisted) | **by-design** (follows sub_agent non-goal) |

---

## D. HTTP surface (PoC monolith → fleet component split)

The PoC `computer-use-server/app.py` is a single web-app exposing Files, Browser,
Terminal, Preview, System, MCP surfaces. The fleet splits these across components; the
gateway owns ONLY the MCP tool-call ingress. Rows below are the PoC endpoints and where
they land in the fleet.

| PoC endpoint (app.py) | fleet owner | verdict |
|---|---|---|
| `GET /api/uploads/{chat}/manifest`, `/list`; `POST /api/uploads/{chat}/{file}` (:357,:394,:419) | ocu-webui (E5 `GET /v1/files`, upload) + #140 attachment leg | **known** (#140 in progress) / **by-design** (webui owns files) |
| `GET /files/{chat}/archive` (:475) — archive download | ocu-webui `downloadArchive` (AGENTS.md:37) + link_filter outlet archive button | **by-design** (webui owns archive; link_filter is a webui function) |
| `GET /files/{chat}/{file}` (:538) — file download | ocu-webui `GET /v1/files/{id}/content` | **by-design** (webui) |
| `GET /api/outputs/{chat}` (:593) — list outputs | ocu-webui `GET /v1/files` list | **by-design** (webui) |
| `GET /preview/{chat}` (:1134) — preview SPA | ocu-webui `previewRender` (AGENTS.md:38) | **by-design** (webui) |
| `GET /browser/{chat}/status|json` (:632,:660,:679) — CDP browser pane | **no fleet analog** | **GAP** (browser-automation pane is a PoC web-app feature; not in fleet MVP scope — likely by-design but uncited; confirm it is intentionally dropped) |
| `GET|POST /terminal/{chat}/...` ttyd, restart, resurrect, sessions, processes, kill, heartbeat (:796-1057) | **no fleet analog** | **GAP** (interactive terminal pane + container lifecycle ops are PoC web-app features; fleet lifecycle is control-internal, no user-facing terminal — likely by-design but uncited) |
| `GET /system-prompt` (:1186) | webui link_filter fetches + control init.sh (#139) | **known** (#139, dev-lead, closed live) |
| `GET /skill-mounts|/skill-list|/api/skill-stats` (:1263,:1280,:1372) | skill_manager (PoC) — no fleet skill-runtime | **GAP** (skill mounts / SKILL.md system is PoC-only; fleet has no skill-runtime analog — scope question) |
| `GET /health` (:1296) | gateway `/health` (G10) + control/webui healthchecks | **parity** |
| `GET /mcp-info` (:1510) | gateway `initialize`/`tools/list` handshake | **parity** (fleet uses the MCP handshake, not a custom info endpoint) |
| `GET /api/runtime/cli` (:1395) | n/a (sub_agent CLI runtime) | **by-design** (sub_agent non-goal) |

---

## Summary — action-worthy findings + resolutions

All six were triaged firsthand by the dev-lead after delivery; resolutions
recorded inline. Findings 1–2 are CLOSED; 3–6 are ruled by-design.

1. **exec/command timeout 120 s → 30 s** (C) — **CLOSED.** Confirmed real and fixed:
   `exec_timeout_seconds=120` set in the policy fixture and on the stand; a `sleep 45`
   went red→green live (was timing out at the 30 s default, now completes under 120 s).
   *Original finding: the fleet inherited the 30 s default silently vs the PoC's 120 s.*

2. **`mount_intent.destination = /workspace` vs guest `/mnt/user-data`** (B) — **CLOSED,
   was a FALSE POSITIVE.** The `/workspace` string came from the dev-lead's own stale,
   untracked host secrets-copy, not the live stand. The live stand always held
   `destination=/mnt/user-data`; the field is live end-to-end (gateway `session.go:246`
   projects `policy.MountIntent` into the create-body, control renders it as-is — the
   control chain was verified firsthand by the control peer). Class closed: the policy is now a
   tracked fixture (@e01b29d) + a README step. *Lesson: an audit read against an
   untracked local copy can surface a phantom gap — the tracked fixture is the truth.*

3. **Vision API / describe-image skills** (A) — **by-design.** The owner excluded the
   skill-runtime / Vision path (a v2 scope item; not in the v1 fleet MVP).

4. **`view` image-resize + binary-hint table** (A) — **by-design.** Image-view and the
   SKILL.md binary-hint UX are v2 scope; the fleet `view` is text/dir only for v1
   (CONSTITUTION §III). Recorded as a v1↔v2 feature delta, not a v1 gap.

5. **CPU cap 1.0 → 2 cores** (C) — **by-design** (intentional fleet headroom; a cap, not
   a floor).

6. **Browser pane, Terminal pane, Skill mounts** (D) — **by-design.** The owner excluded
   these PoC web-app subsystems as v1 non-goals of the canon (fleet MVP is chat + files,
   not the full IDE-like panes).

**Excluded per dispatch (not re-derived):** chat-attachment upload leg (#140, webui
peer); default-model system prompt (#139); flat guest view (ADR-0029); admin↔control
metrics (ADR-0022). All confirmed present/tracked, not re-audited.

**Net:** no open parity gap after triage. Two findings were real (exec timeout — fixed;
mount destination — a false positive from a stale local copy, the tracked fixture was
always correct); the rest are deliberate v1-scope decisions.
