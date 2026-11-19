# Five-minute Demonstration Guide

## 0:00–0:35 — Introduction
Introduce SENTINEL-X as an individual defensive cybersecurity project. Explain that it analyses authorised authentication logs and presents explainable indicators for human review.

## 0:35–1:15 — Architecture
Show the React frontend, FastAPI backend, Python detection module and SQLite database. Explain the CSV-to-analysis-to-alert workflow.

## 1:15–2:00 — Import sample data
Open the dashboard and import backend/sample_data/sample_authentication_logs.csv. Explain the required fields and validation controls.

## 2:00–3:15 — Detection and events
Show the imported event ledger. Explain AUTH-001 (repeated authentication failures) and AUTH-002 (successful login following repeated failures). Emphasise that these are rule-based indicators, not proof of compromise.

## 3:15–4:15 — Alert management
Open the Alerts Centre. Show severity, source IP, rule identifier and event count. Change an alert from open to investigating or resolved.

## 4:15–5:00 — Conclusion and limitations
Show the analysis summary. State that this prototype analyses uploaded CSV data, not live network traffic; it does not attribute attacks or replace an enterprise SIEM. Briefly mention future improvements such as authenticated analyst roles, audit trails and streaming ingestion.
