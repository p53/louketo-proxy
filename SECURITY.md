# Security Policy

## Reported Security issues

- CVE-2020-14359 keycloak-gatekeeper: gatekeeper bypass via cURL when using lower case HTTP headers

  Inconsistency in EnableDefaultDeny option implementation, it applies default deny on all UPPERCASE HTTP METHODS, not lowercase, this can be workarounded for existing versions by explicitly listing all methods in different letter case (which is error prone and cumbersome). Fix was delivered in version 1.4.0

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.4.    | :white_check_mark: |

## Reporting a Vulnerability

For security issues please email to pavol.ipoth@protonmail.com or direct message @p53 on discord
