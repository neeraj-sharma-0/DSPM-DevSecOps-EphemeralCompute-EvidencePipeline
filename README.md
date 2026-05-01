# DSPM for DevSecOps Pipelines — Ephemeral Compute, Data Governance, and Evidence

## Overview

Implements DSPM lifecycle controls within DevSecOps pipelines, focusing on **ephemeral compute environments** where sensitive data can be introduced, processed, and unintentionally persisted.

CI/CD pipelines are a critical but under-governed data surface. Build logs, artifacts, environment variables, and intermediate outputs can expose sensitive data without structured audit or deletion controls.

This repository applies DSPM principles to **pipeline execution environments**, enabling classification, audit, policy enforcement, and controlled deletion with evidence.

---

## Core Objective

> Apply DSPM controls to CI/CD pipelines to detect, audit, and control sensitive data exposure, with structured evidence and verifiable cleanup of ephemeral artifacts.

---

## What This Project Does

Within a simulated DevSecOps pipeline, the system:

1. **Ingests pipeline inputs**
   - source files
   - configuration
   - environment variables (simulated)

2. **Classifies data**
   - sensitivity levels
   - PII and secrets
   - ownership and source

3. **Processes pipeline stages**
   - build
   - test
   - artifact generation

4. **Audits outputs**
   - scans logs, artifacts, and intermediate data
   - computes risk scores and severity

5. **Applies policy gate**
   - pass/fail based on critical/high thresholds

6. **Generates evidence artifacts**
   - CSV audit reports
   - JSON policy decisions
   - SHA256 receipts

7. **Executes cleanup (destroy phase)**
   - deletes pipeline artifacts and temporary data
   - records closure with proof-of-absence flag

---

## DSPM Lifecycle Coverage

| Stage    | Implementation                                              |
|----------|-------------------------------------------------------------|
| Discover | Detection across pipeline inputs and outputs                |
| Classify | Sensitivity, PII, secrets, owner, source                    |
| Audit    | Risk scoring across logs, artifacts, and outputs            |
| Enforce  | Policy gate within pipeline execution                       |
| Destroy  | Artifact cleanup with count-based verification              |

---

## Pipeline Risk Surface

DevSecOps pipelines can expose sensitive data through:

- build logs containing secrets  
- environment variables in runtime  
- generated artifacts (binaries, reports)  
- cached outputs across stages  

This repository treats each as a **measurable governance surface**.

---

## Destroy Phase

Pipeline artifacts are deleted and verified using:

- `count_before`
- `count_after`
- `proof_of_absence: true` when `count_after == 0`

> Verification is **count-based only**.  
> Persistence in external systems or logs outside pipeline scope is not evaluated.

---

## Evidence Output

Artifacts generated per run:

- `pipeline_inputs.csv`
- `classification.csv`
- `audit_report.csv`
- `risk_findings.json`
- `policy_gate.json`
- `pipeline_metadata.json`
- `destroy_closure.json`
- `manifest.json`
- `receipts.json`

Outputs written to:
out/evidence/<pipeline_run_id>/


Supports:
- audit traceability  
- reproducibility  
- compliance documentation  

---

## Example Run

- pipeline stages executed: build → test → artifact  
- records processed: 75  
- high severity findings: 9  
- policy gate: FAIL  
- artifacts generated: yes  
- destroy phase: completed  
- count_before: 75  
- count_after: 0  
- proof_of_absence: true  

---

## Scope and Limitations

This repository:

- does not integrate with real CI/CD systems (GitHub Actions, Jenkins, etc.)
- does not validate external log retention systems
- does not guarantee deletion across distributed storage layers

Focus is limited to:
- pipeline-level governance simulation  
- lifecycle control enforcement  
- structured evidence generation  

---

## Why This Matters

CI/CD pipelines are a high-frequency execution layer where:

- sensitive data can leak rapidly  
- artifacts persist beyond intended scope  
- governance controls are inconsistent  

This project demonstrates how DSPM principles can be applied to **pipeline runtime environments**, enabling:

- visibility into data exposure  
- policy-based control  
- controlled cleanup  
- audit-ready evidence  

---

## One-Line Summary

> DSPM governance framework for DevSecOps pipelines with classification, audit, policy enforcement, and verifiable cleanup of ephemeral artifacts.
