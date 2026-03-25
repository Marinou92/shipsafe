---
name: shipsafe
description: Free lite edition of ShipSafe for scanning repos for leaked secrets, unsafe public env usage, wildcard CORS, production console logging, select('*') overfetching, missing security headers, exposed source maps, and basic .env or .gitignore issues. Use this skill for a quick pre-deploy safety scan without auth review, RLS analysis, handler analysis, or auto-fix.
---

# ShipSafe

## Overview

ShipSafe Lite is the public version of ShipSafe. It focuses on secrets, config hygiene, and basic production-safety checks. It does not review auth logic, access control, Supabase RLS, SQL migrations, or API handlers.

## Workflow

### 1. Classify

This edition is report-only. It never edits files.

### 2. Map The Repo

Identify:

- framework and runtime
- client versus server code boundaries
- config files such as `.env`, `.gitignore`, `next.config.*`, and build settings

### 3. Run The Scanner

From the repo root:

```bash
python3 scripts/scan_repo.py --root . --format markdown
```

### 4. Report

Return:

- a single score out of 100
- findings ordered by severity
- file and line references when available
- a short recommended fix for each finding

## Lite Scope

- hardcoded secrets and leaked credentials
- missing `.env` rules in `.gitignore`
- missing `.env.example`
- dangerous `NEXT_PUBLIC_*` usage
- wildcard CORS
- production `console.log`
- `select('*')` overfetching
- missing security headers
- exposed source maps

## Not Included

- auth logic review
- `getSession()` versus `getUser()` analysis
- Supabase RLS or SQL migration review
- handler authorization analysis
- dependency audit normalization
- auto-fix or baseline support
