# Summary

During a penetration testing engagement on a government attendance management system, a critical vulnerability was discovered: jQuery 1.10.2 (released in 2013, 11 years old) affected by CVE-2019-11358 - Prototype Pollution.
Key Findings
AspectDetailsVulnerabilityCVE-2019-11358 - Prototype Pollution in jQueryAffected VersionjQuery 1.10.2 (EOL since 2016)CVSS Score6.1 (Medium) → HIGH in contextAttack VectorNetwork (Client-Side & Potential Server-Side)Status✅ Fixed - jQuery upgraded to 3.7.1
Impact

✅ Prototype Pollution Confirmed - Object.prototype can be modified
⚠️ Property Injection Possible - Additional properties can be injected into objects
❌ Server Validation Present - Backend properly validates and sanitizes input
🔍 Client-Side Risk - Potential XSS and client-side manipulation

Target:        Government Attendance Management System
Domain:        absensi.pasuruankota.go.id
System Type:   Web Application (PHP - CodeIgniter)
jQuery Version: 1.10.2 (Released: May 24, 2013)
Testing Date:  December 2024
Authorization: ✅ Authorized Penetration Testing

# Vulnerability Details
CVE-2019-11358: Prototype Pollution
Description:
jQuery before 3.4.0 is vulnerable to Prototype Pollution via the $.extend() function when performing deep object merging. The vulnerability allows an attacker to modify Object.prototype through the __proto__ property.
