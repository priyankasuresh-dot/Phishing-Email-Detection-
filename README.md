# Phishing-Email-Detection-
This lab shows a step-by-step method to investigate suspicious emails and determine if they’re phishing. It uses tools like MxToolbox, VirusTotal, IPVoid, urlscan.io, and Hybrid Analysis plus Gmail’s Show Original to verify sender authenticity and check domain/IP reputation.
# Why detect phishing?

Phishing emails attempt to trick recipients into revealing credentials or downloading malware. Detecting phishing:

Verifies message authenticity.

Exposes malicious links or attachments before users click them.

Prevents credential theft and financial loss.

Builds user awareness of safe email practices.

# Tools used (brief)

MxToolbox — DNS / MX / SPF / DKIM / DMARC lookup and blacklist checks.

VirusTotal — Multi-engine scanning for domains, URLs, IPs, and files.

IPVoid — IP reputation, ASN, geolocation, and blacklist checks.

urlscan.io — Safe URL crawl, redirect chain, and screenshot of rendered page.

Hybrid Analysis — Sandbox analysis of files/URLs for malicious behavior.

Gmail “Show original” — Raw headers to verify SPF/DKIM/DMARC and extract sending IPs.

# Key concepts

SPF, DKIM, DMARC: Email authentication records that help prove an email’s origin and integrity.

Plaintext indicators: Phishing commonly uses mismatched sender display names vs. authenticated domains, unusual reply-to addresses, and urgent/pressure language.

Link behavior: Redirects to unrelated domains or credential harvesting pages are strong phishing indicators.

# Step-by-Step Procedure (concise)

Identify the suspicious email

Note subject, displayed sender, and any urgent action request (e.g., “Security alert”).

Extract and inspect headers

In Gmail: Show original → check SPF, DKIM, DMARC results and the Received: chain to locate the originating IP(s).

Domain & DNS checks (MxToolbox)

Query MX, SPF, DKIM, DMARC, and blacklist status for the sending domain.

Lack of proper records or blacklist hits increases suspicion.

URL / domain reputation (VirusTotal, IPVoid)

Submit sender IP, sending domain, and any URLs shown in the email to VirusTotal and IPVoid.

Review detection ratios, related URLs/domains, and ASN/owner information.

Safe URL analysis (urlscan.io)

Submit the suspicious link to urlscan.io to view redirects, resource requests, and a screenshot of the rendered page without opening it locally.

Check whether redirects stay within the expected domain or jump to unknown hosts.

Behavioral analysis (Hybrid Analysis)

If attachments or URL-hosted payloads are present, run them in a sandbox to look for network callbacks, credential-stealing behavior, or file drops.

Cross-check outcomes & timeline

Correlate header timestamps, capture times, and any evidence from scanning tools.

If SPF/DKIM/DMARC pass and tools show no malicious detections, the message is likely legitimate.

Decision

If authentication fails or tools show malicious behavior → mark as phishing and follow incident response steps.

If authentication passes and all scans are clean → mark as legitimate and document findings.

# Case example (summary of the analyzed email)

Subject: Security alert

From: Google <no-reply@accounts.google.com>

Headers: SPF = PASS, DKIM = PASS, DMARC = PASS

Sending IP: 209.85.220.73 — verified as Google infrastructure (MxToolbox / IPVoid / VirusTotal clean).

URL: Redirects to accounts.google.com → myaccount.google.com (urlscan.io screenshot and VirusTotal show no malicious activity).

Hybrid Analysis: No suspicious behavior.

# Conclusion: Email is a legitimate Google security alert (not phishing).

# Recommendations & Best Practices

Never click suspicious links — inspect links with urlscan.io or VirusTotal first.

Always check raw headers to confirm SPF/DKIM/DMARC and the true sending IP.

Use multi-layer checks — domain, IP, URL, and sandboxing together reduce false negatives.

Train users: Simulated phishing exercises and awareness training reduce successful attacks.

Automate where possible: Integrate URL/IP scanning into mailflow (SIEM / email gateway) to auto-block high-risk messages.

Benefits of this project

Hands-on familiarity with practical email investigation tools.

Improved ability to distinguish legitimate notifications from phishing.

Demonstrates how layered checks (DNS auth, reputation, sandboxing) give high-confidence results.

Helps organizations build repeatable workflows for email triage.

# Safety & Ethics

Perform scans and sandboxing only on content you are authorized to test. Respect privacy and legal considerations when sharing captured headers or payloads.

# Summary

This project provides a repeatable lab process to analyze suspicious emails: extract headers, verify authentication (SPF/DKIM/DMARC), check domain/IP/URL reputation, perform safe URL/sandbox analysis, and conclude whether the email is phishing. The illustrated example showed a legitimate Google security alert — all checks passed.
