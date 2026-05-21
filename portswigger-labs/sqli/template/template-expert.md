## Goal
Research-grade documentation. Show you can think like an attacker and a security engineer. 700–1000 words. This is blog-publishable content.

## Lab details
Lab: [Lab name]

Level: Expert

Vulnerability Class: SQL Injection — [subtype]

Lab URL: [PortSwigger lab link]

Date Completed: [Date]

Time to Solve: [Honest — expert labs often take hours or days]

## Overview
[3–4 sentences. What makes this lab expert-level? What does it require that apprentice/practitioner labs don't? Why does this matter in the real world?]

## Background: The Concept Being Exploited
[Explain the underlying concept as if writing for a technical blog. This section is what makes expert writeups publishable.]

## Example:
"Boolean-based blind SQLi relies on the application returning different responses for true vs. false conditions. When no visible difference exists in the HTTP response, time-based techniques use conditional delays (e.g., SLEEP() in MySQL, pg_sleep() in PostgreSQL) to infer information one bit at a time. This is slower but effective when out-of-band channels are unavailable."


## Threat Model
AttackerAccess RequiredImpactCVSS Estimate[e.g., Unauthenticated][e.g., HTTP request to search endpoint][e.g., Full DB read, credential extraction][e.g., 9.8 Critical]

## Reconnaissance & Methodology
Phase 1: Identifying the injection point
[Detail your enumeration process]
Phase 2: Confirming exploitability
[What confirmed the vulnerability? What edge cases did you hit?]
Phase 3: Data extraction strategy
[How did you plan the extraction before executing it?]

## Exploitation — Detailed Walkthrough
Step 1: [Name]
sql[payload]
Observation: [What happened]
Interpretation: [What it means]
Step 2: [Name]
sql[payload]
Observation:
Interpretation:
[Continue for all steps]

## Final Payload Chain
sql-- Annotated final payload
[payload with inline comments explaining each component]

Obstacles & How I Resolved Them
[Expert labs have filters, WAFs, or unusual behaviors. Document what blocked you and how you worked around it. This section is what makes expert writeups genuinely valuable to other researchers.]
ObstacleWhat I TriedWhat Worked[e.g., Single quotes filtered][e.g., Hex encoding, double encoding][e.g., CHAR() function bypass]

## Defense-in-Depth Analysis
[Go beyond "use prepared statements." Think like an AppSec engineer designing the full defensive stack.]
Layer 1 — Input validation:
[What validation should exist at the API boundary?]
Layer 2 — Parameterized queries:
java// Stack-specific fix
[code]
Layer 3 — Least privilege:
[What DB permissions should the app user have? What should be explicitly denied?]
Layer 4 — Error handling:
[How should the app handle SQL errors without leaking schema information?]
Layer 5 — Detection:
[What would this attack look like in logs? What WAF rule or SIEM alert would catch it?]

## CVE / Real-World Reference
[Find and reference a real CVE or disclosed bug report that uses the same technique. Link it. Explain the parallel.]

## Connections to My Own Projects
[Did you test subscription-manager for this? What did you find? Even "I verified my app is not vulnerable because X" is valuable — document the verification.]

What I'd Do Differently / What I'd Research Next
[Your researcher voice. Where does this technique lead? What advanced variant would you explore next?]

## TL;DR — One Paragraph Summary
[Write a clean, plain-English summary of the lab, technique, and fix. This is what you'd post on LinkedIn when you share the writeup.]

### Published on: [your blog URL]
### GitHub: [link to your portswigger-web-security repo]