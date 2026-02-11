# Detection-as-Code Tools

Detection-as-Code Tools is a **DaC** repository designed to standardize the creation, validation, and deployment of detection rules across multiple security platforms. It provides a structured, automation-ready framework that enables security engineering teams to manage detections as version-controlled code artifacts—improving consistency, traceability, reviewability, and operational scalability.

The repository supports rule definition using **TOML for metadata and configuration**, **Sigma for detection logic**, and **Python-based tooling** for validation and SIEM deployment.

By adopting this approach, teams can move from ad-hoc, platform-specific rule management to a **repeatable, auditable, and automated detection engineering workflow**.

---

## Core Concepts

This repository is built around the following principles:

- **Detection-as-Code** – Detections are treated as code artifacts (versioned, reviewed, tested, and deployed like software).
- **Platform abstraction** – Sigma rules provide vendor-agnostic detection logic that can be converted into SIEM-specific query languages.
- **Automation-ready** – Designed to integrate into CI/CD pipelines for validation, packaging, and deployment.

### Detection-as-Code
All detection logic and metadata are stored as code. This allows teams to:

- Use **version control** for detections
- Track changes over time (diffs, history, authorship)
- Enforce peer reviews and approvals
- Standardize structure and required fields
- Integrate detections into CI/CD pipelines

### Platform Abstraction (Sigma)
Detection logic is written in **Sigma**, an open, platform-agnostic detection rule format. This enables:

- A single source of truth for detection logic
- Portability across SIEM platforms
- Reduced vendor lock-in
- Faster multi-platform deployment

Sigma rules can be translated into platform-specific queries during deployment.

### Automation-Ready
The tools in this repository are structured to support automation at every stage of the detection lifecycle:

- Automated validation of metadata and schema requirements
- Guardrails to prevent broken rules from shipping
- CI/CD compatibility for scalable rule management
- Deployment scripts that push content to target platforms

---

## Repository Layout

```text
.
├── rules/
│   └── *.toml
├── sigma/
│   └── *.yml
├── elasticuploader.py
├── splunkuploader.py
├── validator.py
└── README.md
```

## Directory and File Overview

### `rules/`
Contains **TOML rule definition files**.

Each TOML file typically includes:

- Rule metadata (title, description, severity, tags, references, etc.)
- Mapping to the associated Sigma rule (or detection logic identifier)
- Deployment configuration and runtime parameters

These files act as the **control layer** for rule lifecycle management and deployment behavior.

### `sigma/`
Contains **Sigma detection logic files** (`*.yml`).

These files define:

- The detection conditions and logic
- Log source definitions
- Selection clauses and filters
- Matching conditions

Sigma rules are vendor-neutral and can be translated into platform-specific queries (e.g., Elastic, Splunk).

### `elasticuploader.py`
Python-based uploader responsible for:

- Translating rules into Elastic-compatible artifacts (as applicable)
- Uploading and updating rules in Elastic
- Managing authentication and API interactions
- Supporting repeatable deployments

### `splunkuploader.py`
Python-based uploader used to:

- Convert detection logic into Splunk searches (as applicable)
- Upload, update, or manage detection content in Splunk
- Automate deployment workflows

### `validator.py`
Validation utility that:

- Validates TOML structure and required fields
- Detects schema issues, missing values, or malformed inputs
- Prevents invalid detections from being deployed

This script is intended to be used locally and/or in CI as a gating control.

---

## Typical Workflow

A standard detection engineering workflow using this repository looks like:

1. **Create or update a Sigma rule** in `sigma/`.
2. **Create or update the corresponding TOML metadata/config** in `rules/`.
3. **Run validation** using `validator.py` to ensure the rule is structurally correct and references are valid.
4. **Commit changes** to version control (with review/approval as needed).
5. **CI/CD pipeline runs validation** and optionally packages/translates rules for target platforms.
6. **Deployment scripts** (`elasticuploader.py`, `splunkuploader.py`) push updates to the SIEM(s).

---

## Benefits

Using this repository provides several operational advantages:

- **Consistency at scale** — standardized rule structure and metadata requirements
- **Auditability** — full history of changes, reviews, and ownership via git
- **Portability** — Sigma logic enables vendor-agnostic detections
- **Lower operational risk** — validation prevents broken/malformed rules from deploying
- **Faster deployments** — automation reduces manual work and turnaround time
- **Better collaboration** — rules can be reviewed like code and improved iteratively

---

## Contact Us

If you’re interested in implementing a full-scale Detection-as-Code program, need enterprise-grade detection content, or want to learn more about automated detection pipelines, visit our Detection-as-Code offering:

**Detection-as-Code Feed:**  
https://blackcell.io/detection-as-code-dac/

Our DaC Feed provides continuously updated, production-ready detection content designed for modern security operations.
