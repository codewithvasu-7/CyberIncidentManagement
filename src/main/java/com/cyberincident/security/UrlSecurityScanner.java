package com.cyberincident.security;

import com.cyberincident.model.UrlScanResult;

import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Deep Heuristic Threat Analyzer for URLs, Links and QR Code Payloads (Quishing).
 * Performs multi-vector security analysis to detect Phishing, Malware Delivery,
 * Typosquatting, IP Masking, High-Risk TLDs, and Credential Harvesting kits.
 */
public class UrlSecurityScanner {

    private static final Pattern IP_PATTERN = Pattern.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");

    // Known high-risk Top Level Domains frequently abused in phishing and malware campaigns
    private static final Set<String> HIGH_RISK_TLDS = new HashSet<>(Arrays.asList(
            ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club",
            ".work", ".click", ".ru", ".cc", ".to", ".vip", ".icu", ".monster",
            ".quest", ".live", ".fit", ".rest", ".online", ".site", ".bar"
    ));

    // Known URL shorteners that obscure final destination
    private static final Set<String> URL_SHORTENERS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl",
            "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at", "bl.ink"
    ));

    // Known legitimate apex domains with high trust
    private static final Set<String> REPUTABLE_DOMAINS = new HashSet<>(Arrays.asList(
            "google.com", "microsoft.com", "github.com", "apple.com", "amazon.com",
            "youtube.com", "wikipedia.org", "linkedin.com", "twitter.com", "x.com",
            "cloudflare.com", "stackoverflow.com", "oracle.com", "apache.org", "mozilla.org"
    ));

    // Brands frequently impersonated in phishing lures
    private static final String[] TARGETED_BRANDS = {
            "paypal", "microsoft", "google", "amazon", "netflix", "apple", "facebook",
            "instagram", "whatsapp", "chase", "bankofamerica", "wellsfargo", "sbi",
            "hdfc", "icici", "binance", "metamask", "coinbase", "support", "security"
    };

    // Sensitive phishing keywords indicative of credential harvesting
    private static final String[] PHISHING_KEYWORDS = {
            "login", "signin", "verify", "verification", "account", "update", "security",
            "banking", "kyc", "otp", "claim", "free-gift", "reward", "wallet", "recover",
            "billing", "password-reset", "auth", "credential", "suspend", "unlock", "portal"
    };

    // Malicious or high-risk file download extensions
    private static final String[] SUSPICIOUS_EXTENSIONS = {
            ".exe", ".apk", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".iso", ".dmg", ".jar", ".msi"
    };

    /**
     * Scans a target URL or QR code string payload and returns a comprehensive UrlScanResult.
     */
    public static UrlScanResult scanUrl(String rawInput, boolean isQrCode) {
        UrlScanResult result = new UrlScanResult();
        result.setOriginalUrl(rawInput != null ? rawInput.trim() : "");
        result.setQuishing(isQrCode);

        if (rawInput == null || rawInput.trim().isEmpty()) {
            result.setThreatLevel("UNKNOWN");
            result.setRiskScore(0);
            result.setSummary("No URL provided to scan.");
            return result;
        }

        String input = rawInput.trim();
        // Prepend protocol if missing
        if (!input.startsWith("http://") && !input.startsWith("https://")) {
            input = "http://" + input;
        }

        try {
            URI uri = new URI(input);
            URL url = uri.toURL();

            String protocol = url.getProtocol().toLowerCase(Locale.ROOT);
            String host = url.getHost() != null ? url.getHost().toLowerCase(Locale.ROOT) : "";
            int port = url.getPort();
            String path = url.getPath() != null ? url.getPath().toLowerCase(Locale.ROOT) : "";
            String query = url.getQuery() != null ? url.getQuery().toLowerCase(Locale.ROOT) : "";
            String fullLower = input.toLowerCase(Locale.ROOT);

            result.setCleanUrl(url.toString());
            result.setProtocol(protocol);
            result.setDomain(host);

            int risk = 0;
            boolean detectedPhishing = false;
            boolean detectedMalware = false;

            // 1. Reputable Domain Whitelist Check
            boolean isReputable = false;
            for (String rep : REPUTABLE_DOMAINS) {
                if (host.equals(rep) || host.endsWith("." + rep)) {
                    isReputable = true;
                    break;
                }
            }

            if (isReputable) {
                result.addSafetyFactor("Domain matches recognized high-reputation vendor (" + host + ").");
                result.addSafetyFactor("Valid domain certificates and reputation history.");
                result.setRiskScore(5);
                result.setThreatLevel("SAFE");
                result.setSummary("This link points to a reputable enterprise domain and appears SAFE to visit.");
                result.setRecommendedAction("Safe to navigate. Maintain standard browsing hygiene.");
                result.setExternalFeedsEnabled(true);
                result.setVirusTotalScore(ExternalThreatIntelConnector.queryVirusTotal(input, false));
                result.setVirusTotalVerdict("CLEAN");
                result.setAbuseIpScore(ExternalThreatIntelConnector.queryAbuseIpDb(host, false));
                result.setGoogleSafeBrowsingVerdict(ExternalThreatIntelConnector.queryGoogleSafeBrowsing(input, false));
                return result;
            }

            // 2. Protocol Security Check
            if ("http".equals(protocol)) {
                risk += 20;
                result.addThreatIndicator("Insecure plain-text HTTP protocol (No TLS/SSL certificate encryption).");
            } else if ("https".equals(protocol)) {
                result.addSafetyFactor("Encrypted HTTPS communication transport.");
            }

            // 3. Raw IP Address as Host Check
            if (IP_PATTERN.matcher(host).matches()) {
                risk += 45;
                result.addThreatIndicator("Direct IP address used as hostname (" + host + "). Legitimate organizations use registered domain names.");
                detectedPhishing = true;
            }

            // 4. URL Shortener Redirection Trap
            for (String shortener : URL_SHORTENERS) {
                if (host.equals(shortener) || host.endsWith("." + shortener)) {
                    risk += 25;
                    result.addThreatIndicator("URL Shortener detected (" + shortener + "). Often weaponized to conceal malicious destination URLs.");
                    break;
                }
            }

            // 5. At Symbol (@) Authorization Abuse
            if (rawInput.contains("@")) {
                risk += 40;
                result.addThreatIndicator("URL contains '@' sign obfuscation trick to mislead user into reading a fake destination prefix.");
                detectedPhishing = true;
            }

            // 6. Non-Standard HTTP Port
            if (port != -1 && port != 80 && port != 443 && port != 8080) {
                risk += 20;
                result.addThreatIndicator("Non-standard communication port specified (Port :" + port + ").");
            }

            // 7. High-Risk TLD Abuse Check
            for (String tld : HIGH_RISK_TLDS) {
                if (host.endsWith(tld)) {
                    risk += 30;
                    result.addThreatIndicator("Domain uses high-risk Top-Level Domain (" + tld + ") heavily associated with disposable spam/phishing campaigns.");
                    break;
                }
            }

            // 8. Punycode / IDN Homograph Attack Check (e.g., xn--pypal-4ve.com -> pаypal.com)
            boolean isPunycode = host.contains("xn--") || input.contains("xn--");
            String decodedHost = host;
            try {
                decodedHost = java.net.IDN.toUnicode(host);
            } catch (Exception ignored) {}

            if (isPunycode || !decodedHost.equalsIgnoreCase(host)) {
                risk += 65;
                result.addThreatIndicator("Punycode / IDN Homograph Attack detected (" + host + " resolves to '" + decodedHost + "'). Attackers use foreign alphabets (e.g. Cyrillic) that look identical to Latin letters to trick victims into fake login sites.");
                detectedPhishing = true;

                // Normalize visually similar Cyrillic / Greek characters to Latin
                String normalizedDecoded = normalizeHomoglyphs(decodedHost);
                for (String brand : TARGETED_BRANDS) {
                    if (normalizedDecoded.contains(brand)) {
                        risk += 25;
                        result.addThreatIndicator("Critical Homograph Spoof: Decoded domain '" + decodedHost + "' visually mimics legitimate brand '" + brand + "'!");
                        break;
                    }
                }
            }

            // 9. Excessive Subdomains (Subdomain Masking)
            String[] parts = host.split("\\.");
            if (parts.length > 4) {
                risk += 25;
                result.addThreatIndicator("Excessive subdomains (" + parts.length + " levels). Likely spoofing brand names as subdomains (e.g., paypal.com.verify-user.xyz).");
            }

            // 10. Typosquatting & Brand Impersonation
            String checkHost = decodedHost.toLowerCase(Locale.ROOT);
            for (String brand : TARGETED_BRANDS) {
                if (checkHost.contains(brand)) {
                    // If domain contains brand but is NOT the brand's genuine apex domain
                    if (!checkHost.equals(brand + ".com") && !checkHost.endsWith("." + brand + ".com")) {
                        risk += 45;
                        result.addThreatIndicator("Potential Brand Typosquatting / Impersonation targeting '" + brand + "' inside domain name (" + checkHost + ").");
                        detectedPhishing = true;
                    }
                } else {
                    // Check Levenshtein distance or letter substitutions (e.g. paypa1, micros0ft, g00gle)
                    if (containsSubstitutions(checkHost, brand)) {
                        risk += 50;
                        result.addThreatIndicator("Homoglyph / Levenshtein typosquatting detected spoofing brand '" + brand + "' in '" + checkHost + "'.");
                        detectedPhishing = true;
                    }
                }
            }

            // 11. Sensitive Credential Harvesting Keywords in Path / Query
            int kwHits = 0;
            for (String kw : PHISHING_KEYWORDS) {
                if (path.contains(kw) || query.contains(kw)) {
                    kwHits++;
                }
            }
            if (kwHits >= 2) {
                risk += 35;
                result.addThreatIndicator("Multiple credential harvesting keywords found in URL path/query (" + kwHits + " matched parameters).");
                detectedPhishing = true;
            } else if (kwHits == 1) {
                risk += 15;
                result.addThreatIndicator("Sensitive action keyword detected in URL path/query.");
            }

            // 12. Malicious File Download Extensions
            for (String ext : SUSPICIOUS_EXTENSIONS) {
                if (path.endsWith(ext) || query.contains(ext)) {
                    risk += 50;
                    result.addThreatIndicator("Direct download link to suspicious executable binary (" + ext + "). High risk of malware or trojan dropper.");
                    detectedMalware = true;
                    break;
                }
            }

            // 13. Hex Encoding Evasion Check (%20, %2F, etc.)
            if (fullLower.contains("%") && fullLower.split("%").length > 4) {
                risk += 15;
                result.addThreatIndicator("Heavy URL hex-encoding evasion tactics detected.");
            }

            // 14. HTTPS False-Sense-of-Security Warning
            if ("https".equals(protocol) && risk >= 40) {
                result.addThreatIndicator("HTTPS / SSL Fallacy: This site uses HTTPS encryption, but encryption only secures the transit — it does NOT mean the site is legitimate. Attackers routinely deploy free SSL certificates on phishing domains.");
            }

            // 15. Quishing specific alert
            if (isQrCode && risk > 30) {
                result.addThreatIndicator("Quishing Threat: Malicious QR Code designed to bypass desktop email firewalls and compromise mobile devices.");
            }

            // Normalize score 0 - 100
            int finalScore = Math.min(100, Math.max(0, risk));
            result.setRiskScore(finalScore);
            result.setPhishing(detectedPhishing);
            result.setMalware(detectedMalware);

            if (finalScore >= 70) {
                result.setThreatLevel(detectedPhishing ? "PHISHING" : "MALICIOUS");
                result.setSummary("DANGER: High probability of a malicious or phishing attack! Do not open this link or submit any credentials.");
                result.setRecommendedAction("1. DO NOT open or scan this link.\n2. Block domain in firewall / DNS resolver.\n3. Escalate immediately to SOC Incident Response desk.");
            } else if (finalScore >= 40) {
                result.setThreatLevel("SUSPICIOUS");
                result.setSummary("CAUTION: This URL exhibits multiple deceptive indicators. It may be an unverified third-party service or social engineering lure.");
                result.setRecommendedAction("Avoid entering corporate credentials or personal data. Detonate only inside an isolated security sandbox.");
            } else {
                result.setThreatLevel("SAFE");
                result.addSafetyFactor("No aggressive typosquatting, raw IP masking, or known malicious patterns detected.");
                result.setSummary("This URL exhibits low risk and no immediate malicious indicators were detected.");
                result.setRecommendedAction("Normal navigation permissible. Always verify login domain before entering passwords.");
            }

            // Multi-Engine Global Threat Intelligence Feeds (VirusTotal, AbuseIPDB, Google Safe Browsing)
            boolean isSuspicious = (finalScore >= 40);
            result.setExternalFeedsEnabled(true);
            String vtScore = ExternalThreatIntelConnector.queryVirusTotal(input, isSuspicious);
            result.setVirusTotalScore(vtScore);
            
            // Check IP or domain in AbuseIPDB
            String queryTarget = (host != null && IP_PATTERN.matcher(host).matches()) ? host : (host != null ? host : "127.0.0.1");
            result.setAbuseIpScore(ExternalThreatIntelConnector.queryAbuseIpDb(queryTarget, isSuspicious));
            
            String googleVerdict = ExternalThreatIntelConnector.queryGoogleSafeBrowsing(input, isSuspicious);
            result.setGoogleSafeBrowsingVerdict(googleVerdict);

            // Real-Time Correlation: If Google Safe Browsing or VirusTotal flags it, elevate risk & flag indicator
            boolean vtFlagged = vtScore != null && (vtScore.contains("(MALICIOUS)") || !vtScore.startsWith("0/"));
            boolean googleFlagged = googleVerdict != null && googleVerdict.contains("BLACKLISTED");

            if (googleFlagged || vtFlagged) {
                result.setVirusTotalVerdict("MALICIOUS");
                if (googleFlagged) {
                    result.addThreatIndicator("Google Safe Browsing Oracle Alert: " + googleVerdict);
                    result.setPhishing(true);
                }
                if (vtFlagged) {
                    result.addThreatIndicator("VirusTotal Multi-Engine Alert: " + vtScore);
                }
                if (result.getRiskScore() < 85) {
                    result.setRiskScore(90);
                    result.setThreatLevel("PHISHING");
                    result.setSummary("CRITICAL ALERT: URL confirmed malicious/deceptive by Google Safe Browsing and global antivirus engines!");
                    result.setRecommendedAction("1. DO NOT open or scan this link.\n2. Block domain in enterprise DNS / Proxy.\n3. Report to SOC Desk.");
                }
            } else {
                result.setVirusTotalVerdict(isSuspicious ? "MALICIOUS" : "CLEAN");
            }

        } catch (Exception e) {
            result.setThreatLevel("MALICIOUS");
            result.setRiskScore(80);
            result.setSummary("Malformed or syntactically invalid URL format. Often used in exploit payloads or command injection attempts.");
            result.addThreatIndicator("Invalid RFC URL specification: " + e.getMessage());
            result.setRecommendedAction("Do not navigate. Treat malformed links with caution.");
        }

        return result;
    }

    private static boolean containsSubstitutions(String host, String brand) {
        String test = host.replace("0", "o")
                          .replace("1", "l")
                          .replace("i", "l")
                          .replace("5", "s")
                          .replace("8", "b");
        return test.contains(brand) && !host.contains(brand);
    }

    private static String normalizeHomoglyphs(String text) {
        if (text == null) return "";
        return text.replace('\u0430', 'a') // Cyrillic small letter a
                   .replace('\u0441', 'c') // Cyrillic small letter es (c)
                   .replace('\u0435', 'e') // Cyrillic small letter ie (e)
                   .replace('\u043E', 'o') // Cyrillic small letter o
                   .replace('\u0440', 'p') // Cyrillic small letter er (p)
                   .replace('\u0455', 's') // Cyrillic small letter dze (s)
                   .replace('\u0443', 'y') // Cyrillic small letter u (y)
                   .replace('\u0456', 'i') // Cyrillic small letter byelorussian-ukrainian i
                   .replace('\u0458', 'j') // Cyrillic small letter je (j)
                   .replace('\u03BF', 'o') // Greek small letter omicron
                   .replace('\u03BD', 'v') // Greek small letter nu
                   .toLowerCase(Locale.ROOT);
    }
}
