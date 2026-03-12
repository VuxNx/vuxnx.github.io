---
title: 0-day in Kerberos.io/Agent
published: 2026-03-12
description: ''
image: ''
tags: [vuln-research, 0day]
category: 'write-up'
draft: false 
lang: ''
---

## Overview

In early March 2026, I discovered a critical zero-day vulnerability (CVSS 9.8) in the ```kerberos-io/agent project```. I responsibly disclosed the issue to the vendor via email. The Kerberos team responded promptly, acknowledged the severity of the flaw, and quickly released a patch in ```PR #257```. 

::github{repo="kerberos-io/agent"}

This write-up details the technical discovery of a complete Authentication Bypass within the Agent's API endpoints. The vulnerability stems from an improper implementation of the Gin HTTP Router middleware, allowing an unauthenticated, remote attacker to gain full unauthorized administrative access, extract sensitive camera configurations, and perform Denial of Service (DoS) attacks.

---

## Affected Product
- **Product**: kerberos-io/agent
- **Affected Versions**: All versions prior to 3.6.14

---

## Details
In the `routes.go` file (`machinery/src/routes/http/routes.go`), the `/api` router group is defined, and numerous sensitive endpoints (such as `POST /api/config`, `POST /api/camera/stop`, `GET /api/camera/snapshot/base64`, etc.) are attached to this group. 

At the bottom of the implementation, the JWT authentication middleware is applied using the Gin framework's `Use()` function. However, in Gin, middleware added via `Use()` only applies to the routes registered *after* the `Use()` invocation. Because the block following the middleware is completely empty and no routes are defined subsequently, the authentication middleware is never actually applied to any endpoints. 

As a result, every single API endpoint meant to be protected is world-accessible without any credentials.

## PoC
To verify this vulnerability, an attacker simply needs to send standard HTTP requests to any of the sensitive endpoints without providing an `Authorization` header or a JWT:
`curl -X GET "http://[AGENT_IP]/api/config"`

## Impact
An unauthenticated, remote attacker can trivially exploit this flaw to:
* Extract sensitive system and camera configuration, including RTSP credentials (`GET /api/config`).
* Reconfigure the agent, redirect the camera feed, or alter system behavior (`POST /api/config`).
* Perform Denial of Service (DoS) attacks by stopping or restarting the agent (`POST /api/camera/stop`, `POST /api/camera/restart`).
* Continuously monitor the live camera feed and stored recordings without authorization (`GET /api/camera/snapshot/jpeg`, `GET /api/latest-events`, etc.).

## Remediation
This issue has been patched in ```Pull Request #257```.

## Disclosure Timeline
* **March 07, 2026:** Discovered the zero-day vulnerability. Sent the initial vulnerability report and PoC via email to `support@uug.ai` and `support@kerberos.io`.
* **March 10, 2026:** Opened a benign GitHub issue (#256) to notify the maintainers about the security email without disclosing sensitive details.
* **March 10, 2026:** The maintainer (@cedricve) responded, acknowledged the vulnerability, and confirmed it was patched in PR #257. The vendor authorized me to request a CVE.
* **March 10, 2026:** The vendor updated their repository with a new `SECURITY.md` file to establish a formal private security disclosure policy.
* **March 12, 2026:** Created and submitted the private Security Advisory via GitHub to officially request the CVE identifier.
* **[To be updated]:** CVE ID assigned by GitHub/MITRE.
* **[To be updated]:** Public disclosure of this write-up.


