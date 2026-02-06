# Detection-as-Code Tools

Detection-as-Code Tools is a **Detection-as-Code (DaC)** repository designed to standardize the creation, validation, and deployment of detection rules across multiple security platforms. It enables security engineering teams to manage detections as version-controlled code, improving consistency, reviewability, and automation.

The repository supports rule definition using **TOML for metadata and configuration**, **Sigma for detection logic**, and **Python-based tooling** for validation and SIEM deployment.

---

## Core Concepts

This repository is built around the following principles:

- **Detection-as-Code** – Detections are treated as code artifacts
- **Platform abstraction** – Sigma rules provide vendor-agnostic detection logic
- **Automation-ready** – Designed to integrate into CI/CD pipelines

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