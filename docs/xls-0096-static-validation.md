# XLS-0096 static validation (commit 799693a23 + fixups)

Target: `feature/xls-0096-confidential-mpt` at `799693a23` plus the five
small follow-ups through `6f7a643eb`.

Source of truth: XLS-0096-confidential-mpt (Draft, 2026-01-15).
Secondary reference: merged Confidential Transfer on XRPLF/rippled `develop`.
Out of scope: holder key rotation/update.

Method: 12 subsystem find-passes, then each candidate re-checked by three
independent reviewers against this tree. Only findings that survived that
adversarial pass (or that all three reviewers agreed exist as spec/wire
mismatches) are listed. No build or execution.

**Critical: none. High: none.**

The compact-sigma and Bulletproof layers did not yield a confirmed soundness
bug. The clawback HIGH candidate (issuer can burn a partial amount, then wipe
the rest and ghost COA) was **disproved**: `verifyClawbackSigma` proves the
on-ledger `sfIssuerEncryptedBalance` encrypts exactly `MPTAmount`.

---

## Confirmed defects

### Medium

1. **`ConfidentialMPTMergeInbox` omits `requireAuth`**
   - Spec: §9.2.1.2 item 4 — `lsfMPTRequireAuth` and missing `lsfMPTAuthorized`
     → `tecNO_AUTH`.
   - Code: `ConfidentialMPTMergeInbox::preclaim` (`ConfidentialMPTMergeInbox.cpp:27-48`)
     never calls `requireAuth`. `ConfidentialMPTSend` does (`ConfidentialMPTSend.cpp:96-99`).
   - Votes: 2 confirm / 1 reject (rejecter treated it as non-theft).
   - Impact: after an issuer later enables RequireAuth or unauthorizes a holder,
     that holder can still merge inbox → spending and bump
     `sfConfidentialBalanceVersion`. They still cannot `ConfidentialMPTSend`
     without auth. Spec-mandated authorization gate is missing on merge.

2. **Clawback tears down confidential fields instead of EncZero + `version++`**
   - Spec: §11.4 — spending, inbox, issuer mirror, and auditor mirror are set
     to EncZero; `sfConfidentialBalanceVersion` increments by 1. §7.4 — an
     `MPToken` that has initialized confidential fields cannot be deleted,
     even when those fields are EncZero.
   - Code: `clearConfidentialState` (`ConfidentialMPT.cpp:103-117`) removes
     the holder key and every confidential field, including the version.
     `ConfidentialMPTClawback::doApply` always calls it after a successful
     proof (`ConfidentialMPTClawback.cpp:92-98`).
   - `MPTokenAuthorize` then allows deletion whenever
     `sfHolderEncryptionKey` is absent (`MPTokenAuthorize.cpp:86-93`,
     `MPTokenHelpers.cpp:183-204`). The lifecycle test deletes Alice’s
     `MPToken` after clawback while global COA is still 5
     (`ConfidentialMPT_test.cpp:424-440`).
   - Votes: 1 reject / 1 downgrade / 1 partial-confirm. Partial-clawback
     theft was rejected; the EncZero / deletion-blocker mismatch stands.
   - Impact: no on-ledger EncZero residue after clawback; the holder object
     can vanish while confidential circulation continues for other holders.
     Secondary-reference docs still describe EncZero + version bump.

3. **Issuance create/set flag encoding does not match the draft tables**
   - Spec: `tfMPTCanHoldConfidentialBalance` (create) = `0x00000100`;
     `tfMPTSetCanHoldConfidentialBalance` (set) = `0x00000100` on `Flags`;
     `lsifMPTCanHoldConfidentialBalance` on `sfImmutableFlags` = `0x00000080`.
   - Code:
     - Create uses `TF_FLAG(..., lsfMPTCanHoldConfidentialBalance)` =
       `0x00000080` (`TxFlags.h:136-144`, `LedgerFormats.h:181`).
     - Set enable is `tmfMPTSetCanHoldConfidentialBalance = 0x00001000` on
       `sfMutableFlags`, not `Flags` (`TxFlags.h:378-379`).
     - Mutability is inverted `lsmfMPTCannotEnableCanHoldConfidentialBalance`
       on DynamicMPT `sfMutableFlags` (`LedgerFormats.h:190-192`).
   - Votes: 3/3 rejected as a *security* bug (documented DynamicMPT alignment).
     Listed because the draft is the source of truth: a spec-faithful client
     sending `Flags: 256` is `temINVALID_FLAG` here.
   - Impact: wire / client interoperability with the published draft.

### Low

4. **Send does not independently reject hidden amounts above `maxMPTokenAmount`**
   - Spec: §5.4 — Bulletproof range is `[0, 2^64)`; transactors independently
     reject values above `maxMPTokenAmount` (`2^63-1`).
   - Code: `proveBulletproofSend` / `verifyBulletproofSend` use 64-bit range
     and positivity via `m-1` (`bulletproof.cpp:24`, `1145-1175`).
     `ConfidentialMPTSend` never consults `kMaxMpTokenAmount`.
   - Votes: 1 confirm / 1 downgrade / 1 reject.
   - Impact: a holder cannot accumulate more than OA ≤ MA through Convert, so
     this is defense-in-depth / spec text, not a demonstrated inflation path.

5. **`sfConfidentialBalanceVersion` wrap is incompatible with the invariant**
   - Spec: §9.3 — version increments and wraps from `UINT32_MAX` to 0.
   - Code: `incrementConfidentialVersion` wraps (`ConfidentialMPT.cpp:85-91`).
     `ValidConfidentialMPT` requires `after == before + 1` when spending
     changes (`MPTInvariant.cpp:692-698`).
   - Votes: 1 confirm / 2 reject (impractical).
   - Impact: after 2^32 spending mutations the next Send/Merge/ConvertBack
     fails closed (`tecINVARIANT_FAILED`). Not theft; theoretical liveness.

6. **Clawback Fiat–Shamir context omits the spending version**
   - Spec: Appendix A.7 — proofs bind transaction type, issuer/currency, and
     version counters.
   - Code: `transactionContextIDClawback` is
     `(txType, issuer account, issuance ID, sequence, holder)` —
     no `sfConfidentialBalanceVersion` (`confidential.h:201-206`).
     Send and ConvertBack do bind the version.
   - Matches the same-ledger race class reported against the merged
     Confidential Transfer implementation (clawback-then-send in one ledger:
     Send proof is stale; submitter still pays the 10× fee).
   - Replay of an old clawback proof is still blocked by the ciphertext
     binding (`C2 = m·G + sk·C1` on the current issuer mirror).

7. **TER table mismatches (operation still rejected)**
   - Send missing destination: `tecNO_DST` vs spec `tecNO_TARGET`
     (`ConfidentialMPTSend.cpp:87-88`). Clawback uses `tecNO_TARGET`.
   - Freeze: `tecLOCKED` vs spec `terFROZEN`. `terFROZEN` does not exist in
     this tree; MPT helpers already map freeze to `tecLOCKED`.
   - Votes: 3/3 rejected as security issues (TER-name-only).

8. **Documented crypto-parameter omissions (consensus-stable here, not in the draft)**
   - Pedersen `H` is try-and-increment from `SHA512Half("CMPT_NUMS_H"||counter)`
     (`confidential.h:152-158`, `confidential.cpp:593-627`).
   - EncZero `r` retries with a counter when the first reduction is 0
     (`confidential.cpp:128-159`).
   - EncZero’s third domain field is `makeMptID` (issuance ID), not a classic
     currency code (`ConfidentialMPT.cpp:72-78`).
   - Votes: 3/3 rejected as exploits (deterministic in this tree). Listed
     because another implementation following only the draft prose can disagree.

---

## Extra transaction (not a defect in the five-tx set)

`ConfidentialMPTReencryptAuditor` (type 90) implements the two-phase auditor
migration described conceptually in §13.2.1. The draft’s transaction table is
types 85–89 only. Holder key rotation was not reviewed.

---

## Rejected HIGH / CRITICAL candidates

| Claim | Why it failed re-check |
| --- | --- |
| Clawback can prove a partial `m` then wipe leftover value / ghost COA | Sigma proves `C2 = m·G + sk·C1` on the *on-ledger* issuer mirror. A different `m` cannot verify. The lifecycle test’s “40 of 45 COA” is Alice’s *full* remaining confidential (she sent 10 of 50); Carol still holds 5. |
| ConvertBack `COA==0` wipes a non-zero inbox | ConvertBack `m` is bound to spending. `COA' = 0` and `m ≤ spending` and `COA ≥ spending+inbox` imply inbox = 0. |
| `finalizeInvariants` no-ops skip MPT checks | Per-tx hooks are unused (3.2.0). `ApplyContext::checkInvariants` still runs `ValidConfidentialMPT` / `ValidMPTPayment`. |
| `ValidMPTPayment` soft-fails under `featureMPTokensV2` | Pre-existing on `d4c135992`; confidential only added `confidentialDelta` to that checker. |
| Missing issuer/auditor mirror updates are a live desync | `ValidConfidentialMPT` requires the full field set; Convert seeds mirrors on init. Unreachable from a valid ledger. |

---

## Scope notes

- Amendment gate, 10× fee, issuer-as-holder prohibition, transfer-fee XOR
  confidential, deposit-auth / credentials on Send, and EncZero merge reset
  match the draft in substance.
- Follow-ups `2523403d4` (delegate key-registration permission) and
  `6f7a643eb` (`ValidConfidentialMPT` on `tec*`) were treated as already fixed.
