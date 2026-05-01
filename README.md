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
