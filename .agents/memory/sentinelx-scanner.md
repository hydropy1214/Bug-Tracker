---
name: SentinelX scanner setup
description: Real security tools installed and how scanner.ts uses them for genuine network scanning
---

## Real tools installed (Nix system packages)
- nmap 7.97 — TCP port scanning + service detection (-sV -sT -T4)
- whois 5.6.2 — domain WHOIS (some whois servers blocked by sandbox network)
- dnsutils/dig — DNS enumeration (A, AAAA, MX, TXT, NS, CAA, SOA, AXFR attempts)

## External free APIs (no auth required)
- ipinfo.io — IP geolocation and ASN enrichment
- crt.sh — SSL certificate transparency for subdomain discovery
- Wayback Machine CDX API — historical endpoint discovery

## Scanner phases (artifacts/api-server/src/lib/scanner.ts)
12 phases total. Which phases run depends on scan type:
- recon: DNS(dig), IP geo, WHOIS, TLS(openssl+node:tls), HTTP headers, fingerprinting
- enumeration: + nmap ports, subdomain discovery (crt.sh + DNS brute), sensitive paths, Wayback
- vulnerability: + web app probes (SQLi, XSS, open redirect), API surface
- full: all 12 phases

**Why:** user wanted real tools not just Node.js built-ins.

## Database
- Replit managed PostgreSQL — DATABASE_URL is runtime-managed, never set manually
- Schema push: pnpm --filter @workspace/db run push
