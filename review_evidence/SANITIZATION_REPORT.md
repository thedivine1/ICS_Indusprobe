# Publication Safety & Sanitization Audit Report

**Date of Inspection**: 2026-11-11  
**Inspection Workspace**: `/Users/tejas/Documents/chaitanya/ICS/IndusProbe-public-review`  
**Methodology**: Multi-pass automated regex scanning, AST verification, and manual inspection.  

---

## 1. Checks Actually Performed

The proposed public review snapshot was evaluated across all staged files using the following automated and manual inspection rules:

1. **Secret & Credential Patterns**:
   - Regex matching for private keys: `-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----`
   - Regex matching for GitHub personal access tokens: `ghp_[A-Za-z0-9_]{30,}`, `github_pat_[A-Za-z0-9_]{30,}`
   - Regex matching for API keys and tokens: `(password|secret|token|api_key|bearer)\s*[:=]\s*['"][^'"]{4,}['"]`
   - Inspection of `.env`, `.env.example`, and configuration files.

2. **Customer Names & Plant Context**:
   - Whole-word regex search for known corporate client names (e.g. `UltraTech`, `Adani`, `Holcim`, `Lafarge`).
   - Inspection of sample report headers, site locations, IP subnets, and facility unit names.

3. **Developer-Specific Absolute Paths**:
   - Regex search for `/Users/[a-zA-Z0-9_-]+/` across all code, script, documentation, and fixture files.

4. **Third-Party Licensing & Redistribution Rights**:
   - Identification of all third-party repositories, license files, and copyleft/non-commercial clauses.

5. **Symlink Traversal**:
   - Verification that no symbolic links point outside the review workspace.

---

## 2. Findings & Disclosures

### A. Secrets and Authentication Tokens
- **Finding**: **Zero secrets or hardcoded credentials detected.**
- No API keys, password literals, bearer tokens, or private SSH keys were identified in any staged file.

### B. Customer and Plant Confidentiality
- **Finding**: **All customer-identifying files excluded.**
- The real client assessment report (`reports/IndusProbe_UltraTech_Cement_Works_...`) was completely excluded from the snapshot.
- The retained sample report in `sample_reports/` represents a fictional facility:
  `Demonstration Cement Plant — Clinker Line 2` (Synthetic 5,000 TPD Clinker Line).

### C. Developer-Specific Absolute Paths
- **Finding**: Absolute paths were located in two source scripts:
  1. `generate_cement_report.py`: Line 364 originally hardcoded `/Users/tejas/Documents/chaitanya/ICS/IndusProbe/reports`. **Sanitized** to `./reports`.
  2. `indus_probe/otforge_test.py`: Lines 21 and 23 reference `/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/...`.  
     *Disclosure*: In accordance with the instruction not to alter core application code behavior during snapshot preparation, `otforge_test.py` was left untouched in `indus_probe/`. This script is documented in `REVIEW_START_HERE.md` and `docs/passive_safety_findings.md` as an ad-hoc developer runner that is not expected to run on clean reviewer systems.
  3. Documentation files (`docs/actual_usage_map.md`, `docs/passive_safety_findings.md`, `docs/proposed_remediation_plan.md`): Contain explicit developer path citations specifically describing the local audit findings. These citations are contextual narrative and do not affect runtime execution.

### D. Third-Party Code & Licensing Notice
- **Finding**: **All external cloned repositories are excluded.**
- `IndusProbe/external_repos/` (which housed `devkid/profinet`, `pycomm3`, `pylogix`, and `zeek-plugin-profinet`) and adjacent clones (`GasPot`, `conpot`, `labshock`, etc.) were excluded in their entirety.
- **Notice**: External clones are excluded from this snapshot. Code provenance, historical adaptation history, and third-party license obligations have not been independently verified. No warranty of cleanroom development or complete freedom from licensing restrictions is made.

### E. Symlinks
- **Finding**: **Zero symlinks present.**
- `find . -type l` confirmed that zero symbolic links exist in the review workspace.

---

## 3. Remaining Uncertainties

1. **No Guarantee of Secret-Free State**: While extensive automated regex and manual checks revealed zero secrets, static heuristic analysis cannot mathematically guarantee the absence of all conceivable token formats or obfuscated credentials.
2. **PCAP Sample Provenance**: The external test PCAP files referenced by `otforge_test.py` reside in `industrial-scanner/pcaps/` (an external repository). Because that repository is excluded, the exact network environment from which those historical captures originated cannot be independently verified from this snapshot.
3. **Draft Documentation Provenance**: Document `docs/is16335:2015.md` contains a markdown transcription of Indian Standard IS 16335:2015 security controls for review reference.

