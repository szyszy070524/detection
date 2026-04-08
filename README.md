# SkillScope

SkillScope is a static, browser-only website for reviewing skill ZIP packages before you trust them.

It exists for a simple reason: the current safety baseline around community-distributed skills is too low. A ZIP can contain Python, JavaScript, or shell automation that most users never inspect. This project is a small public attempt to improve that situation with transparent, local-first review tooling.

## What this site does

- Accepts one `.zip` skill bundle at a time
- Extracts the archive entirely in the browser
- Recursively traverses nested folders
- Detects suspicious Python, JavaScript, and shell patterns
- Produces a `0-100` safety score
- Highlights high-risk findings in red, guarded findings in yellow, and low-risk bundles in green

## Privacy promise

This website does not upload your files to any server.

Extraction, parsing, scanning, and scoring all happen locally in your browser tab.

## Why this project exists

This repository is not presented as a perfect security solution. It is an advocacy project and a practical starting point.

The main point is simple:

- skill ecosystems currently have weak default transparency
- users often install or trust automation they did not really inspect
- basic static review should be easier, faster, and local-first

If this repository helps push the ecosystem toward safer defaults, clearer review standards, and better tooling, then it is doing its job.

## How to use

### Local development

1. Install dependencies:

```bash
npm install
```

2. Start the dev server:

```bash
npm run dev
```

3. Open the local URL shown by Vite in your browser.

### Production build

```bash
npm run build
```

The static output will be generated in `dist/`.

### Website usage

1. Open the site in your browser.
2. Upload a single skill ZIP package.
3. Wait for local extraction and scanning to finish.
4. Review the overall score, verdict, and file-by-file findings.
5. Manually inspect any file that triggers high-risk or critical behavior.

## Detection model

SkillScope uses heuristic static analysis only. It does not run uploaded scripts.

Current rule groups include:

- user and machine identity collection
- environment variable access
- command execution
- dynamic code execution
- file system access
- network and exfiltration behavior
- sensitive keyword targeting
- dynamic module loading
- dangerous system libraries
- system mutation and file deletion
- obfuscation and encoded payloads
- background execution
- download-and-execute chains
- credential path targeting
- install hooks and auto-run entrypoints

### Detection coverage

| ID | Detection item | Severity | What it looks for |
| --- | --- | --- | --- |
| `identity-collection` | Identity collection | Medium | Username, hostname, machine name, or other local identity lookups |
| `env-access` | Environment variable access | High | Reads from environment variables that may expose secrets or tokens |
| `command-exec` | System command execution | Critical | `os.system`, `subprocess`, `child_process`, shell execution, spawned commands |
| `dynamic-exec` | Dynamic code execution | Critical | `eval`, `exec`, dynamic `Function`, string-based timed execution |
| `file-access` | File system access | Medium | Local file reads, writes, path traversal, stream creation, direct shell reads |
| `network-exfil` | Network or exfiltration | Critical | HTTP requests, sockets, `fetch`, `curl`, `wget`, outbound transfer behavior |
| `sensitive-harvest` | Sensitive data targeting | High | Mentions or searches for cookies, passwords, tokens, API keys, emails, secrets |
| `dynamic-import` | Dynamic module loading | Medium | Runtime imports, indirect requires, dynamic module resolution |
| `dangerous-libs` | Dangerous system libraries | Medium | Low-level system or process libraries often used for host control |
| `system-mutation` | System mutation | High | File deletion, permission changes, recursive removal, destructive local changes |
| `obfuscation` | Obfuscation or encoded payloads | High | `base64`, `marshal`, packed payloads, encoded content, compressed loaders |
| `background-exec` | Background execution | Medium | Threads, multiprocessing, daemon tasks, detached or hidden background work |
| `download-exec` | Download and execute chain | Critical | Patterns like `curl | sh`, remote download followed by immediate execution |
| `credential-targeting` | Credential file targeting | High | Direct references to `.env`, `.ssh`, `.npmrc`, keys, cookies, keychains |
| `autorun-hooks` | Auto-run install hooks | Medium | `postinstall`, `preinstall`, `bootstrap`, setup and entrypoint style auto-run hooks |

### Combination penalties

The scanner also applies extra deductions when multiple risky behaviors appear together in the same file:

| Combination | Extra penalty | Why it matters |
| --- | --- | --- |
| Command execution + network behavior | `-15` | Can fetch remote content and immediately run commands |
| Environment access + network behavior | `-15` | Can read secrets and send them out |
| Dynamic execution + obfuscation | `-15` | Can hide payloads and execute them at runtime |
| System mutation + background execution | `-10` | Can alter the machine and keep running silently |

## Important limitation

This is not a sandbox, not a malware lab, and not a guarantee that a bundle is safe.

It is an early warning layer designed to make obvious and moderately hidden risks easier to spot before execution.

## Contributing

Anyone can support this codebase and help iterate on it, improve it, expand detections, refine scoring, or improve the interface.

Useful contribution areas:

- stronger detection rules
- lower false positives
- better visual reporting
- broader language support
- more transparent rule explanations
- test archives and benchmark cases

## Contact

For collaboration, feedback, upgrades, or broader discussion:

- Email: [szyszy070524@163.com](mailto:szyszy070524@163.com)

Conversations are welcome.
