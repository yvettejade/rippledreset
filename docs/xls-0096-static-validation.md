# XLS-0096 static validation — commit `799693a23` only

Target: `799693a23e3cc3726dd6000405849f0c4bce383f`
("Implement XLS-0096 confidential MPT transfers and protocol updates").

This pass does **not** include the five later fixups on
`feature/xls-0096-confidential-mpt` (`440d564c7` … `6f7a643eb`).
Crypto / transactor logic at `799693a23` is the same as those fixups
(formatting and include order only). Two follow-ups change behavior;
those holes are in scope here.

Source of truth: XLS-0096-confidential-mpt (Draft, 2026-01-15).
Out of scope: holder key rotation/update. No build or execution.

**Critical: none.**

---

## High (present at `799693a23`, fixed later)

1. **Any issuer delegate can register confidential keys and mutate issuance**
   - `MPTokenIssuanceSet::checkPermission` at this commit: if the delegate
     lacks transaction-level `MPTokenIssuanceSet`, the function still
     returns `tesSUCCESS` unless the tx carries `tfMPTLock`/`tfMPTUnlock`
     without the matching granular permission.
   - Encryption keys, `sfMutableFlags`, `sfTransferFee`, metadata, and
     `sfDomainID` are fields, not `sfFlags`. They never hit
     `tfMPTokenIssuanceSetMask` (`0x01|0x02`).
   - Consequence: a Delegate SLE from the issuer to Bob for *Payment*
     (or lock-only) is enough for Bob to submit `MPTokenIssuanceSet` as
     the issuer and register `IssuerEncryptionKey` / `AuditorEncryptionKey`,
     or set `tmfMPTSetCanHoldConfidentialBalance`.
   - Payment’s granular path fails closed (`terNO_DELEGATE_PERMISSION`
     when no mint/burn match). IssuanceSet at this commit fails open.
   - Fixed by `2523403d4` (require full `MPTokenIssuanceSet` for key
     registration and other non-lock mutations).
   - Spec §5.5 trusts delegates *within the scope delegated*. This is
     outside that scope — XRPL granular delegation is the security
     boundary, and this bypasses it.

---

## Medium

2. **`ValidConfidentialMPT` is a no-op on `tec*` claimed-failure applies**
   - At this commit:
     `if (!featureConfidentialTransfer || !isTesSuccess(result)) return true;`
     (`MPTInvariant.cpp` `ValidConfidentialMPT::finalize`).
   - `ApplyContext::checkInvariants` runs on both `tesSUCCESS` and `tec*`
     claimed applies. This checker opts out of the `tec*` case.
   - `ConfidentialMPTConvert::doApply` writes public `MPTAmount` and
     `ConfidentialOutstandingAmount` *before* finishing init. A later
     `tecINTERNAL` (holder-count overflow) or `encZeroFor` / parse failure
     persists `Δpublic = -m`, `ΔCOA = +m`, and a partial field set.
     `ValidMPTPayment` also skips non-success results, so neither
     invariant sees the drift.
   - Fixed by `6f7a643eb` (evaluate on `tec*` as well).
   - Impact: claimed-failure Convert/init can leave ghost COA and/or an
     illegal partial confidential field set that later txs mishandle.

3. **`ConfidentialMPTMergeInbox` omits `requireAuth`**
   - Spec §9.2.1.2 item 4: `lsfMPTRequireAuth` and missing
     `lsfMPTAuthorized` → `tecNO_AUTH`.
   - MergeInbox preclaim never calls `requireAuth`. Send does.
   - Same at `799693a23` and at the later tip.

4. **Clawback tears down fields instead of EncZero + `version++`**
   - Spec §11.4 / §7.4. `clearConfidentialState` removes the holder key
     and every confidential field. `MPTokenAuthorize` then allows
     deletion whenever the key is absent, including while global COA > 0
     for other holders.
   - Same at `799693a23`.

5. **Create/set flag encoding does not match the draft tables**
   - Create `tfMPTCanHoldConfidentialBalance` is `0x80` (via `lsf`), not
     spec `0x100`. Set enable is `MutableFlags 0x1000`, not `Flags 0x100`.
   - Immutable form is inverted DynamicMPT
     `lsmfMPTCannotEnableCanHoldConfidentialBalance`.
   - Spec-client interop: `Flags: 256` is `temINVALID_FLAG` here.
   - Same at `799693a23`.

---

## Low

6. **Send does not independently cap hidden amounts at `maxMPTokenAmount`.**
   Bulletproof range is `[1, 2^64)`; spec §5.4 says transactors reject
   above `2^63-1`. Convert cannot accumulate more than OA ≤ MA.

7. **Version wrap vs invariant.** Spec allows `UINT32_MAX → 0`.
   `ValidConfidentialMPT` requires `after == before + 1`. Fails closed
   after 2^32 spending mutations.

8. **Clawback Fiat–Shamir context omits the spending version.**
   Send and ConvertBack bind it. Same-ledger clawback-then-send wastes
   the 10× fee. Replay still blocked by the ciphertext binding.

9. **TER names.** Send missing dest is `tecNO_DST` (spec `tecNO_TARGET`).
   Freeze is `tecLOCKED` (spec `terFROZEN`, which does not exist here).

10. **Crypto parameters the draft does not pin.** Provisional NUMS `H`,
    EncZero zero-scalar counter retry, EncZero domain uses `makeMptID`
    as “Curr”. Deterministic in this tree.

---

## Not in `799693a23` (do not treat as residual)

| Follow-up | What it fixed |
| --- | --- |
| `2523403d4` | Finding 1 — delegate key-registration fail-open |
| `6f7a643eb` | Finding 2 — `ValidConfidentialMPT` on `tec*` |
| `440d564c7` | Levelization / include order only |
| `e3d6c6b40` | clang-format only |
| `129ff80bf` | Test keys (dummy `0x02`/`0x03` bytes were `temMALFORMED` before permission was tested) |

---

## Rejected HIGH (unchanged vs the tip pass)

Partial-clawback COA ghost is still disproved at this commit: the sigma
proves `C2 = m·G + sk·C1` on the on-ledger issuer mirror. ConvertBack
`COA==0` inbox wipe is still not a fund-theft path.
