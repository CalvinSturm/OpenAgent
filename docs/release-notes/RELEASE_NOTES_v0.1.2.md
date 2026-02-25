# LocalAgent v0.1.2 Release Notes

Date: 2026-02-22

## Highlights

- Startup UI refresh with compact `Mode` + `Provider` panes.
- Chat UI refresh with improved header/footer and boxed input row.
- New in-chat mode and timeout controls for faster iteration on local models.

## Startup UX

- Updated startup layout:
  - compact `Mode` + `Provider` panes
  - centered footer controls
  - provider refresh/details controls (`R`, `D`)
- Improved custom flow:
  - selecting `Custom` opens a compact submenu with `Back` + custom toggles
  - menu fits default terminal sizes more reliably

## Chat UX

- Header now shows mode label (`Safe`, `Code`, `Web`, `Custom`) and right-justified `?`.
- Footer now shows explicit `cwd: <absolute path>` and right-justified connection status.
- Input area is now a boxed prompt row above footer/overlay.
- Status line above input uses animated wave + rotating thinking/working phrases.
- Keybind overlay (`?`) rows are aligned uniformly.

## New Slash Commands

- `/mode <safe|coding|web|custom>`
  - switches chat runtime mode in-session
- `/timeout`
  - shows current timeout settings and prompts for next numeric input
- `/timeout <seconds|+N|-N>`
  - sets or adjusts request/stream-idle timeout in-session
- `/dismiss`
  - clears active timeout notification

## Timeout Guidance

- Provider timeout-style failures now emit a guidance notice suggesting `/timeout`.
- Notice can be cleared with `/dismiss`.

## Install / Upgrade

```bash
cargo install --path . --force
localagent version
```
