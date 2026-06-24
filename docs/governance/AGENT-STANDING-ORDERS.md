# Standing orders — building against the corpus

You are building against a tightly-specified architecture (`docs/architecture/`) with a
design corpus (`docs/design/`) as backstop. Resolve every uncertainty in this order. Do not
skip a step; do not improvise past one.

## Escalation order

1. **Corpus first — for *what should this do*.** Check the architecture doc for the contract,
   then the design doc for the derivation behind it. Most "how should this behave" questions
   are already answered or derivable. Resolve against the corpus before writing anything.

2. **Substrate second — for *what does the kernel actually do*.** For binder, namespaces,
   Landlock, seccomp, cgroups: check in this sub-order —
   a. **the existing repo's usage and its test suite** (how Kennel already drives this subsystem — it encodes what the kernel actually honors),
   b. **the kernel source**,
   c. **the kernel documentation** *last*.
   Docs describe the intended contract and mislead on the details that matter (e.g. a flag
   that is a per-node boolean in the struct but reads as a count in the prose). The repo and
   the source are the authority; the docs are a hint.

3. **Ask last — only for the genuinely undecided.** If the corpus is silent *and* the
   substrate doesn't settle it, it's a real open decision. Ask. Don't guess a default into
   existence. (Known-open items live in each chapter's "Open questions" — treat those as
   ask-or-flag, not as yours to silently resolve.)

## The clause that matters most: substrate contradicts corpus → surface UP

If the kernel/repo check shows the corpus is **wrong** — the architecture specifies something
the substrate cannot do, or does differently (the canonical case: a doc claiming an arity the
kernel enforces as a boolean) — this is **not** a local fix and **not** an ordinary question.

- **Do not** patch the code to match reality and move on. That leaves the architecture doc
  asserting the impossible thing — working code, lying contract. That divergence is the exact
  failure this layered split exists to prevent.
- **Do** stop and surface it as a **corpus defect**: name the doc, the claim, and the
  substrate truth that contradicts it. The fix is two parts — the code *and* the doc — and the
  doc fix flows back up into the architecture (and design, if the derivation was wrong too).

A substrate surprise is a finding about the spec, not just about the build. It propagates
upward, or the layers drift.

## Claims track evidence — never over, never under

Separate from resolving uncertainty: how you **report** it. The project's whole stance is *never
overclaim*. Apply it to your own work, in both directions.

- **No status word without its receipt.** "done / built / merged / shipped / verified / passing
  / proven" is a claim, and a claim carries the check that produced it **in the same turn** — the
  grep, the command output, the PR number, the test result. Can't show the check? Then it isn't
  done: write "unverified" or "I haven't checked," not the status word. Inferring status from a PR
  title, a prior summary, or "it should be" is fabrication, however confident it reads.
- **But don't underclaim either.** When the check *is* there, state the result flat — no hedging
  a proven fact, no performed caution, no "shall I proceed?" gate on work already blessed.
  Reflexive hedging is just overclaiming uncertainty. Humility is the claim matching the
  evidence; it is not a tone.
- **Measure before you characterise.** "shrinks / faster / smaller / cheaper" is a measurement;
  run it (`gen-inventory`, a diff stat, a benchmark) and quote the number, or drop the claim.

The tell, for you and the reader both: a confidence word with no evidence beside it is unverified
until proven otherwise.

## One-line version

Corpus for intent → repo-then-source-then-docs for substrate → ask for the undecided → and
when substrate truth contradicts the corpus, **stop and surface it up as a doc defect**, never
patch around it. And every status/measurement claim carries the check that produced it — never
overclaim, never hedge what you've proven.