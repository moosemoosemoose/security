# Rootward

**Rootward** is a lightweight filesystem watchdog designed to monitor file creation and modification events at or near the system root and other sensitive paths.

It focuses on **behavioral signals**, **deterministic rules**, and **clarity over completeness** — prioritizing signal quality, performance, and auditability over exhaustive signature matching.

Rootward is intended to run quietly in the background as a long-lived service, forming the core detection engine of the Rootward ecosystem.

---

### Philosophy

Rootward is not a traditional antivirus.

Instead of attempting to classify every file as “safe” or “malicious,” Rootward observes filesystem behavior and surfaces events that warrant attention.

Detection is based on:
- Filesystem events and context
- Simple, explainable rules
- Heuristic scoring
- Clear reasoning for every alert

This approach favors **trust, transparency, and control** over opaque decision-making.

---

### Project Status

Rootward is under active development.
The design prioritizes correctness, stability, and incremental expansion.

---

# RootWarden

**RootWarden** is the supervisory layer for Rootward.

It provides configuration, review, and response capabilities for events detected by the Rootward engine, allowing operators to inspect, triage, and act on filesystem activity with full context.

RootWarden does not replace Rootward — it builds on it.

---

Add an Architecture section that mirrors the outline we discussed

Add a Non-Goals section (this prevents scope creep)

Add a Why Not YARA / AV note (short, factual)