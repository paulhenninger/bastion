package dev.bastion.email;

import java.util.Locale;

/**
 * What this application accepts as an email address. Pure and offline; the DNS and
 * blocklist checks live in {@link EmailDeliverability}.
 *
 * <p>Exists because Bean Validation's {@code @Email} is far looser than its name:
 * {@code a@b}, {@code user@localhost} and {@code user@!!!} all pass it. Every accepted
 * address becomes a message sent to an address the caller chose, so this is stricter
 * than RFC 5322 on purpose: no quoted local parts, no IP-literal domains, a dotted
 * domain with a real-looking TLD. Internationalised domains are accepted in their
 * punycode ({@code xn--}) form, which is what SMTP needs on the wire anyway.
 */
public final class EmailAddress {

    /** RFC 5321 caps a path at 256 including the angle brackets. */
    public static final int MAX_LENGTH = 254;
    private static final int MAX_LOCAL_LENGTH = 64;
    private static final int MAX_LABEL_LENGTH = 63;
    /** RFC 5322 "atext" minus the dot, which is handled as a separator. */
    private static final String LOCAL_ATOM_CHARS = "!#$%&'*+/=?^_`{|}~-";

    private EmailAddress() {
    }

    /** The canonical form stored and compared: trimmed and lowercased. */
    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    /** A human-readable reason the address is unacceptable, or null when it's fine. */
    public static String problem(String email) {
        if (email == null || email.isBlank()) {
            return "Email is required";
        }
        String value = email.trim();
        if (value.length() > MAX_LENGTH) {
            return "Email must be at most " + MAX_LENGTH + " characters";
        }
        int at = value.indexOf('@');
        if (at < 0 || value.indexOf('@', at + 1) >= 0) {
            return "Email must contain exactly one @";
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        String localProblem = localProblem(local);
        return localProblem != null ? localProblem : domainProblem(domain);
    }

    public static String domainOf(String email) {
        if (email == null) {
            return null;
        }
        int at = email.lastIndexOf('@');
        return at < 0 ? null : email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }

    private static String localProblem(String local) {
        if (local.isEmpty()) {
            return "Email must have something before the @";
        }
        if (local.length() > MAX_LOCAL_LENGTH) {
            return "The part before the @ must be at most " + MAX_LOCAL_LENGTH + " characters";
        }
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..")) {
            return "The part before the @ has a misplaced dot";
        }
        for (int i = 0; i < local.length(); i++) {
            char c = local.charAt(i);
            if (c != '.' && !isAsciiLetterOrDigit(c) && LOCAL_ATOM_CHARS.indexOf(c) < 0) {
                return "Email contains an unsupported character before the @";
            }
        }
        return null;
    }

    private static String domainProblem(String domain) {
        if (domain.isEmpty()) {
            return "Email must have a domain after the @";
        }
        if (domain.startsWith(".") || domain.endsWith(".") || domain.contains("..")) {
            return "The email domain has a misplaced dot";
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            return "The email domain must include a top-level domain, e.g. example.com";
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > MAX_LABEL_LENGTH
                    || label.startsWith("-") || label.endsWith("-")) {
                return "The email domain is malformed";
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (c != '-' && !isAsciiLetterOrDigit(c)) {
                    return "The email domain contains an unsupported character";
                }
            }
        }
        String tld = labels[labels.length - 1].toLowerCase(Locale.ROOT);
        boolean punycode = tld.startsWith("xn--") && tld.length() > 4;
        if (!punycode && (tld.length() < 2 || !tld.chars().allMatch(c -> c >= 'a' && c <= 'z'))) {
            return "The email domain's top-level domain doesn't look right";
        }
        return null;
    }

    private static boolean isAsciiLetterOrDigit(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }
}
