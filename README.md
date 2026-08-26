<div align="center">
  <table style="border: none; border-collapse: collapse; background: transparent; margin: 40px 0 16px 0;">
    <tr style="border: none; background: transparent;">
      <!-- Industrial Terminal Icon -->
      <td style="border: none; padding: 0 14px 0 0; vertical-align: middle;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#46e12a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 17 10 11 4 5"></polyline>
          <line x1="12" y1="19" x2="20" y2="19"></line>
        </svg>
      </td>
      <!-- Big Coding Style Terminal Text -->
      <td style="border: none; padding: 0; vertical-align: middle; white-space: nowrap;">
        <h1 style="border: none; margin: 0; padding: 0; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 34px; font-weight: 800; color: #46e12a; letter-spacing: -0.04em; text-transform: uppercase;">
          A Local-First Safety and Governance Kernel for AI Agents.
        </h1>
      </td>
    </tr>
  </table>
</div>



<p align="center">
  <a href="https://github.com/Rygnal/rygnal-core">
    <img src="https://img.shields.io/badge/core-rygnal--core-black?style=flat-square" alt="rygnal-core" />
  </a>
  <img src="https://img.shields.io/badge/status-early--MVP-orange?style=flat-square" alt="status" />
  <img src="https://img.shields.io/badge/approach-local--first-blue?style=flat-square" alt="local-first" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="license" />
</p>

---

## $$\Large\color{#46e12a}\texttt{What Rygnal builds}$$

Rygnal Core is an **early local-first safety and governance kernel** for evaluating AI coding-agent actions and generated repository patches.

It combines deterministic policy, patch-risk analysis, approval binding, audit evidence, and disposable Git workspaces. The current release is an architecture foundation and must not be presented as production containment.


| Capability | What it does |
| :--- | :--- |
| <code style="color: #4ec9b0;">🛡️ Guarded Review Flow</code> | Evaluates agent requests and generated patches before trusted mutation. |
| <code style="color: #4ec9b0;">📦 Disposable Git Workspace</code> | Generates and reviews changes away from the trusted working tree. This is not OS-level containment. |
| <code style="color: #4ec9b0;">🦀 Rust Semantic Engine</code> | Scores structural AST diffs and temporal decay in `<100ms`. |
| <code style="color: #4ec9b0;">📝 Declarative Guardrails</code> | Shields critical files instantly using a `.rygnal.yaml` list. |
| <code style="color: #4ec9b0;">📋 Tamper-Evident Audit</code> | Hash-chains structured audit events in local JSONL and SQLite storage. |



---

## $$\Large\color{#46e12a}\texttt{Design Principles}$$

| Design Principle | Core Mechanism | Technical Implementation |
| :--- | :--- | :--- |
| <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #4ec9b0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg> Invisible by Default</div> | Zero manual setup | Keeps the developer in their natural terminal flow. The agent remains entirely native until a security boundary is crossed. |
| <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #4ec9b0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg> Zero-Trust Execution</div> | Out-of-process isolation | Denies agents direct write access to the live repository. All file modifications occur within a hidden, deterministic sandbox. |
| <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #4ec9b0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg> Human Context Paramount</div> | Effort-based prioritization | Uses temporal decay formulas and Git history to mathematically protect recently authored human code from AI destruction. |
| <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #4ec9b0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 4 15 12 5 20 5 4"></polygon><line x1="19" y1="5" x2="19" y2="19"></line></svg> Graceful Interception</div> | Inline runtime pausing | Pauses the terminal stream for live human approval, or injects safe system errors so unattended LLMs can self-correct without crashing. |
| <div style="display: flex; align-items: center; gap: 8px; font-weight: 600; color: #4ec9b0;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> Immutable Transparency</div> | Continuous audit logging | Records every AI action, risk score, and system decision to a local, machine-readable `.rygnal/audit.jsonl` state file. |


---

<!-- START OF INDUSTRIAL FOOTER SECTION -->
<br />
<hr style="border: 0; height: 1px; background: linear-gradient(to right, rgba(0,0,0,0), #6366f1, #06b6d4, rgba(0,0,0,0)); margin: 40px 0;" />

<div align="center">
  <table style="border: none; border-collapse: collapse; background: transparent; width: 100%; max-width: 650px;">
    <tr>
      <!-- Open Source / Contributing Column -->
      <td style="border: none; padding: 20px; width: 50%; vertical-align: top; text-align: left;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span style="font-weight: 700; font-size: 16px; letter-spacing: -0.02em; color: #f3f4f6;">Contributing</span>
        </div>
        <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #9ca3af;">
          We welcome bug reports, architecture discussions, and focused pull requests. Review our <a href="./CONTRIBUTING.md" style="color: #06b6d4; text-decoration: none; font-weight: 500;">Contribution Guidelines &rarr;</a> to get started.
        </p>
      </td>
      <!-- Separator Line -->
      <td style="border: none; width: 1px; padding: 0;">
        <div style="width: 1px; height: 100px; background: linear-gradient(to bottom, rgba(0,0,0,0), #374151, rgba(0,0,0,0));"></div>
      </td>
      <!-- System Architecture Ecosystem Column -->
      <td style="border: none; padding: 20px; width: 50%; vertical-align: top; text-align: left;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 16v1a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h11a2 2 0 0 1 2 2v1"/>
            <path d="M18 8h4a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2h-4"/>
            <circle cx="8" cy="12" r="2"/>
          </svg>
          <span style="font-weight: 700; font-size: 16px; letter-spacing: -0.02em; color: #f3f4f6;">Ecosystem</span>
        </div>
        <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #9ca3af;">
          Designed as a local-first architecture foundation for guarded execution, review, and approval workflows. Production containment is not currently implemented.
        </p>
      </td>
    </tr>
  </table>

 