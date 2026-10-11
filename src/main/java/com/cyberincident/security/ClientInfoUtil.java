package com.cyberincident.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Utility for accurately detecting client IP address, device platform,
 * operating system, browser, and formatting timestamps in India Standard Time (IST).
 * Handles Cloudflare tunnels (CF-Connecting-IP, CF-IPCountry), reverse proxies, and IPv6 normalization.
 */
public class ClientInfoUtil {

    // Indian Standard Time Zone (UTC+5:30)
    public static final TimeZone IST_ZONE = TimeZone.getTimeZone("Asia/Kolkata");

    private static final String[] IP_HEADERS = {
            "CF-Connecting-IP",      // Real client IP from Cloudflare Tunnel
            "True-Client-IP",        // Akamai / Enterprise Cloudflare
            "CF-Pseudo-IPv4",        // Cloudflare Pseudo IPv4 (if enabled)
            "X-Forwarded-For",       // Standard reverse proxy
            "X-Real-IP",             // Nginx / Ingress proxy
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
    };

    /**
     * Extracts the real client device IP address, handling Cloudflare and multi-hop proxies.
     */
    public static String getClientIp(HttpServletRequest request) {
        if (request == null) return "127.0.0.1";

        // Check standard headers
        for (String header : IP_HEADERS) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.trim().isEmpty() && !"unknown".equalsIgnoreCase(ip.trim())) {
                // If multiple IPs (e.g. client, proxy1, proxy2), take first IP
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return normalizeIp(ip.trim());
            }
        }

        String remote = request.getRemoteAddr();
        return normalizeIp(remote != null ? remote.trim() : "127.0.0.1");
    }

    /**
     * Normalizes IPv6 loopback and blank values to clean IPv4 or standard IP string.
     */
    public static String normalizeIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return "127.0.0.1";
        }
        ip = ip.trim();
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            return "127.0.0.1";
        }
        return ip;
    }

    /**
     * Determines whether an IP is IPv4, IPv6, or Localhost.
     */
    public static String getIpType(String ip) {
        if (ip == null || ip.trim().isEmpty()) return "Localhost";
        String clean = normalizeIp(ip);
        if ("127.0.0.1".equals(clean) || "localhost".equalsIgnoreCase(clean)) {
            return "Localhost";
        }
        if (clean.contains(":")) {
            return "IPv6";
        }
        return "IPv4";
    }

    /**
     * Formats an IP address for clear UI presentation.
     */
    public static String formatDisplayIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return "127.0.0.1 (Localhost)";
        }
        String clean = normalizeIp(ip);
        if ("127.0.0.1".equals(clean) || "localhost".equalsIgnoreCase(clean)) {
            return "127.0.0.1 (Localhost)";
        }
        return clean;
    }

    /**
     * Analyzes HTTP User-Agent, Client Hints, and client parameters to determine device type, OS, and web browser.
     */
    public static String getDeviceDetails(HttpServletRequest request) {
        if (request == null) return "💻 Desktop • Web Browser";

        // 1. Check client-side fingerprint submitted by forms (login, register, incident reporting)
        String clientFp = request.getParameter("client_device_fingerprint");
        if (clientFp == null || clientFp.trim().isEmpty()) {
            clientFp = request.getParameter("client_device");
        }
        if (clientFp != null && !clientFp.trim().isEmpty() && clientFp.length() <= 100) {
            String fp = clientFp.trim();
            if ((fp.contains("Phone") || fp.contains("Tablet") || fp.contains("Android") || fp.contains("iPhone") || fp.contains("Windows") || fp.contains("Mac") || fp.contains("Linux")) && fp.contains("•")) {
                try {
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.setAttribute("user_device", fp);
                    }
                } catch (Exception ignored) {}
                return fp;
            }
        }

        // 2. Check if already recorded in current user session
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object sessDev = session.getAttribute("user_device");
                if (sessDev instanceof String && !((String) sessDev).isEmpty()) {
                    return (String) sessDev;
                }
            }
        } catch (Exception ignored) {}

        // 3. Inspect Client Hints headers (Modern Chrome, Edge, Chromium Mobile)
        String secChMobile = request.getHeader("Sec-CH-UA-Mobile");
        String secChPlatform = request.getHeader("Sec-CH-UA-Platform");
        String secChModel = request.getHeader("Sec-CH-UA-Model");

        // 4. Fallback to server-side User-Agent parsing
        String ua = request.getHeader("User-Agent");
        String parsed = parseUserAgent(ua, secChMobile, secChPlatform, secChModel);

        try {
            HttpSession session = request.getSession(false);
            if (session != null && parsed != null && !parsed.isEmpty()) {
                session.setAttribute("user_device", parsed);
            }
        } catch (Exception ignored) {}

        return parsed;
    }

    /**
     * Parses a raw User-Agent string into a clean, human-readable Device label with icon.
     */
    public static String parseUserAgent(String ua) {
        return parseUserAgent(ua, null, null, null);
    }

    public static String parseUserAgent(String ua, String secChMobile, String secChPlatform, String secChModel) {
        if (ua == null) ua = "";
        String uaLower = ua.toLowerCase(Locale.ROOT);

        boolean isMobileHint = "?1".equals(secChMobile);
        boolean isAndroidHint = secChPlatform != null && secChPlatform.toLowerCase(Locale.ROOT).contains("android");
        boolean isIosHint = secChPlatform != null && (secChPlatform.toLowerCase(Locale.ROOT).contains("ios") || secChPlatform.toLowerCase(Locale.ROOT).contains("iphone"));

        String os = "Desktop";
        String icon = "💻";

        boolean hasMobileKeyword = uaLower.contains("mobile") || uaLower.contains("mobi") || uaLower.contains("phone");
        boolean hasAndroidKeyword = uaLower.contains("android") || isAndroidHint || uaLower.contains("samsung") || uaLower.contains("sm-") || uaLower.contains("pixel") || uaLower.contains("redmi") || uaLower.contains("xiaomi") || uaLower.contains("oppo") || uaLower.contains("vivo") || uaLower.contains("realme") || uaLower.contains("oneplus") || uaLower.contains("huawei") || uaLower.contains("honor") || uaLower.contains("motorola") || uaLower.contains("moto");
        boolean hasApplePhone = uaLower.contains("iphone") || uaLower.contains("ipod") || isIosHint;
        boolean hasAppleTablet = uaLower.contains("ipad");

        if (hasApplePhone) {
            os = "Apple iPhone (iOS)";
            icon = "📱";
        } else if (hasAppleTablet) {
            os = "Apple iPad (iPadOS)";
            icon = "📱";
        } else if (hasAndroidKeyword || (uaLower.contains("linux") && (hasMobileKeyword || isMobileHint || uaLower.contains("arm") || uaLower.contains("aarch64")))) {
            // Android mobile phone or tablet
            os = uaLower.contains("tablet") ? "Android Tablet" : "Android Phone";
            icon = "📱";
        } else if (isMobileHint || hasMobileKeyword) {
            os = "Mobile Phone";
            icon = "📱";
        } else if (uaLower.contains("windows nt 10.0") || uaLower.contains("windows nt 11.0")) {
            os = "Windows 10/11";
            icon = "💻";
        } else if (uaLower.contains("windows nt 6.3")) {
            os = "Windows 8.1";
            icon = "💻";
        } else if (uaLower.contains("windows nt 6.1")) {
            os = "Windows 7";
            icon = "💻";
        } else if (uaLower.contains("windows")) {
            os = "Windows PC";
            icon = "💻";
        } else if (uaLower.contains("macintosh") || uaLower.contains("mac os x")) {
            os = "Apple Mac (macOS)";
            icon = "💻";
        } else if (uaLower.contains("cros")) {
            os = "Chromebook (ChromeOS)";
            icon = "💻";
        } else if (uaLower.contains("linux")) {
            os = "Linux Desktop";
            icon = "🐧";
        } else {
            os = "Desktop / Web Browser";
            icon = "💻";
        }

        // Detect Web Browser
        String browser = "Browser";
        if (uaLower.contains("edg/") || uaLower.contains("edge/")) {
            browser = "Edge";
        } else if (uaLower.contains("samsungbrowser")) {
            browser = "Samsung Internet";
        } else if (uaLower.contains("chrome/") || uaLower.contains("crios/")) {
            browser = "Chrome";
        } else if (uaLower.contains("firefox/") || uaLower.contains("fxios/")) {
            browser = "Firefox";
        } else if (uaLower.contains("safari/") && !uaLower.contains("chrome/")) {
            browser = "Safari";
        } else if (uaLower.contains("opr/") || uaLower.contains("opera/")) {
            browser = "Opera";
        }

        return icon + " " + os + " • " + browser;
    }

    /**
     * Formats database Timestamp into India Standard Time (IST - Asia/Kolkata).
     * Example: "11 Oct 2026, 09:58:53 AM IST"
     */
    public static String formatIndiaTimestamp(Timestamp ts) {
        if (ts == null) return "N/A";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("dd MMM yyyy, hh:mm:ss a", Locale.ENGLISH);
            sdf.setTimeZone(IST_ZONE);
            return sdf.format(ts) + " IST";
        } catch (Exception e) {
            return ts.toString();
        }
    }

    /**
     * Alias for backwards compatibility.
     */
    public static String formatTimestamp(Timestamp ts) {
        return formatIndiaTimestamp(ts);
    }

    /**
     * Short time format for compact display in India Time: "dd MMM, hh:mm a IST"
     */
    public static String formatShortTimestamp(Timestamp ts) {
        if (ts == null) return "N/A";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("dd MMM, hh:mm a", Locale.ENGLISH);
            sdf.setTimeZone(IST_ZONE);
            return sdf.format(ts) + " IST";
        } catch (Exception e) {
            return ts.toString();
        }
    }

    /**
     * Sanitizes strings for safe HTML rendering to prevent Cross-Site Scripting (XSS).
     */
    public static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }
}
