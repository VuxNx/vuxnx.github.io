---
title: 0-day in Peppermint Ticket Management System
published: 2026-01-24
description: ''
image: ''
tags: [vuln-research, 0day]
category: 'write-up'
draft: false 
lang: ''
---

## Overview

At the beginning of the last week before the end of 2025, I discovered a zero-day vulnerability in the Peppermint Ticket Management System platform. I attempted to reach out via direct message on X in accordance with the Security Policy, but to date I have not received any response. Therefore, this is the reason I am publishing a write-up of the vulnerability I found. 

::github{repo="Peppermint-Lab/peppermint"}

This write-up describes a critical vulnerability chain in the Peppermint Ticket Management System that allows a low-privileged authenticated user to escalate privileges and fully compromise administrative accounts.

The issue arises from the combination of weak password reset code generation, missing verification when changing email addresses, unrestricted user enumeration, and the absence of rate limiting. When chained together, these weaknesses enable reliable administrative account takeover.

---

## Affected Product
- **Product**: Peppermint Ticket Management System  
- **Affected Versions**: Latest available release at the time of testing (as of **2026-01-01**)

---

## Technical Details

### 1. Weak Password Reset Code Generation

**Location**: `apps/api/src/controllers/auth.ts:207–213`

The password reset mechanism generates a 6-digit numeric code using JavaScript’s `Math.random()`. This function is **not cryptographically secure** and produces predictable output when enough samples are observed.

```ts
function generateRandomCode(length = 6) {
  const min = Math.pow(10, length - 1);  // 100000
  const max = Math.pow(10, length) - 1;  // 999999
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
const code = generateRandomCode();
```

**Impacting Factors**
- Use of non-cryptographic PRNG
- No expiration time for reset codes
- No limit on validation attempts

---

### 2. Unverified Email Address Change

**Location**: `apps/api/src/controllers/auth.ts:869–897`

Authenticated users can change their registered email address without confirming their current password

```ts
await prisma.user.update({
  where: { id: session?.id },
  data: { email: email }
});
```

**Issues**
- No password re-authentication

---

### 3. Unrestricted User Enumeration

**Location**: `apps/api/src/controllers/users.ts:11–36`

The `/api/v1/users/all` endpoint exposes user email addresses and administrative status to any authenticated user when role-based access control is disabled (default configuration).

```ts
const users = await prisma.user.findMany({
  select: {
    email: true,
    isAdmin: true
  }
});
```

**Issues**
- Permissions effectively bypassed when `roles_active = false`
- Administrative accounts are clearly identifiable
- Sensitive metadata disclosed to regular users

---

### 4. Missing Rate Limiting on Password Reset

**Location**: `apps/api/src/controllers/auth.ts:255–283`

The password reset verification endpoint lacks rate limiting, allowing unlimited attempts to guess or predict reset codes.

---

## Attack Chain Description

The vulnerabilities above can be combined into a reliable attack path:

### Step 1 – Email Takeover
1. Attacker logs in with a legitimate low-privileged account
2. Changes the account email address to one under attacker control

### Step 2 – Reset Code Collection
3. Triggers multiple password reset requests
4. Collects valid reset codes sent to the attacker-controlled inbox

### Step 3 – User Enumeration
5. Queries `/api/v1/users/all`
6. Identifies administrative accounts and their email addresses

### Step 4 – Code Prediction
7. Generates multiple reset codes for their own account
8. Uses tools such as **v8_rand_buster** to recover the PRNG seed
9. Predicts subsequent password reset codes with high accuracy

### Step 5 – Administrative Account Compromise
10. Triggers a password reset for an administrator account
11. Predicts the valid reset code
12. Resets the administrator password
13. Gains full administrative access

#### Alternative Method for step 4: Brute Force
- 900,000 possible codes
- No rate limiting
- Practical exploitation within minutes using parallel requests

---

## Impact

- Full administrative account compromise
- Complete access to tickets, users, and system configuration
- Potential data breach and integrity loss

---

## Recommendations

- Replace `Math.random()` with `crypto.randomInt()` or equivalent CSPRNG
- Enforce expiration on password reset codes
- Implement strict rate limiting on reset attempts
- Require password re-authentication for email changes
- Add email verification for new addresses
- Restrict `/api/v1/users/all` to administrative roles only

---



