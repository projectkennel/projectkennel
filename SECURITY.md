# Security policy

Project Kennel is a security tool. A vulnerability in it can weaken the confinement it exists to provide. We take reports seriously and ask reporters to follow coordinated disclosure.

## What to report privately

Report **privately** any specific, exploitable weakness in Project Kennel's implementation or design that could let a confined workload:

- escape its kennel or reach resources the policy denies;
- read or write outside its granted filesystem view;
- reach a network destination outside its allowlist, or exfiltrate via an unintended channel;
- escalate privilege, defeat `PR_SET_NO_NEW_PRIVS`, or subvert the privhelper;
- tamper with, forge, or suppress audit events;
- load a policy that violates a framework invariant; or
- otherwise reduce the guarantees stated in the design document and threat catalogue.

This includes weaknesses in the policy compiler, the signature/lockfile verification, the BPF programs, the spawn sequence, the IPC boundaries, and the privhelper.

## What is public, not a vulnerability report

The [threat catalogue](THREATS.md) describes *classes* of risk and is public by design. Documented residual threats (those the design explicitly does not defend against — e.g. T8 in `ai-coding-strict`) are known limitations, not vulnerabilities. A *specific implementation flaw* that breaks a guarantee the design claims to provide is a vulnerability; report it privately.

A *suspected* threat class that the catalogue does not yet cover — where you do not have a specific exploit — is not a private report either: open a public issue tagged `[T-NEW]` (see CONTRIBUTING.md and CODING-STANDARDS.md §13.5). The split is: **specific working exploit → private email; suspected uncatalogued threat class → public `[T-NEW]` issue.** When in doubt, email privately and we will redirect you.

## How to report

Email: **security@projectkennel.org**.

A PGP key for this address may be published alongside this file; if one is present, encrypt sensitive details to it. Do not open a public issue for a specific exploitable flaw.

Include, where you can: affected component and version (commit hash), a description of the weakness, reproduction steps or a proof of concept, the guarantee you believe is broken (cite the design section or threat ID), and any suggested remediation.

## What to expect

- **Acknowledgement** within 72 hours of receipt.
- **Assessment** and a severity judgement, shared with you.
- **Coordinated disclosure** on a timeline matched to severity. We will agree an embargo with you and credit you in the advisory and CHANGELOG unless you prefer otherwise.
- Once a fix lands, the report and any associated threat-catalogue updates become public.

## Scope

In scope: this repository's design, architecture, and (once it exists) reference runtime. Out of scope: vulnerabilities in third-party dependencies (report those upstream; tell us so we can pin or mitigate), and the documented residual threats.
