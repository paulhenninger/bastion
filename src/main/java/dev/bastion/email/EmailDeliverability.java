package dev.bastion.email;

import dev.bastion.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Set;

/**
 * The checks that can refuse a <em>well-formed</em> address being claimed (signup,
 * email change): a known throwaway-mail provider, an undelegated TLD, or a domain
 * that cannot receive mail.
 *
 * <p>Only where an address is being claimed — never at sign-in or recovery: once an
 * address has proven itself by verifying, a lapsed domain or a grown blocklist must
 * not lock its owner out. Each refusal says only what's wrong with the <em>address</em>,
 * never whether it has an account.
 *
 * <p>The MX check <b>fails open on an inconclusive answer, closed on a definite one</b>:
 * a DNS timeout means "we don't know", and refusing every signup during a resolver
 * hiccup is the wrong bargain; an authoritative NXDOMAIN, or a domain with neither MX
 * nor address records, is refused. Lookups are one record type at a time — asking for
 * several at once makes JNDI send an ANY query, which RFC 8482 resolvers refuse, and
 * the check would silently pass everything.
 */
@Component
public class EmailDeliverability {

    private static final Logger log = LoggerFactory.getLogger(EmailDeliverability.class);
    private static final long TOTAL_BUDGET_MS = 3000;

    private final boolean blockDisposable;
    private final boolean checkMx;
    private final Set<String> disposable;
    private final Set<String> tlds;

    public EmailDeliverability(AppProperties props) {
        this.blockDisposable = props.signup().blockDisposable();
        this.checkMx = props.signup().checkMx();
        this.disposable = readList("disposable-email-domains.txt");
        this.tlds = readList("iana-tlds.txt");
    }

    /** Null when the address may be claimed, otherwise a message for the user. */
    public String problem(String email) {
        String domain = EmailAddress.domainOf(email);
        if (domain == null) {
            return null;
        }
        if (blockDisposable && isDisposable(domain)) {
            return "Disposable email addresses can't be used. Please use a permanent address.";
        }
        if (!tlds.isEmpty() && !tlds.contains(domain.substring(domain.lastIndexOf('.') + 1))) {
            return "That email domain doesn't exist. Please check the spelling.";
        }
        if (checkMx && !acceptsMail(domain)) {
            return "That email domain can't receive mail. Please check the spelling.";
        }
        return null;
    }

    /** Matches the domain and every parent, so one entry covers its subdomains. */
    boolean isDisposable(String domain) {
        String candidate = domain;
        while (true) {
            if (disposable.contains(candidate)) {
                return true;
            }
            int dot = candidate.indexOf('.');
            if (dot < 0) {
                return false;
            }
            candidate = candidate.substring(dot + 1);
        }
    }

    private boolean acceptsMail(String domain) {
        long deadline = System.currentTimeMillis() + TOTAL_BUDGET_MS;
        DirContext ctx = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", "1500");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            ctx = new InitialDirContext(env);
            for (String type : new String[]{"MX", "A", "AAAA"}) {
                Answer answer = lookup(ctx, domain, type);
                // RFC 5321 §5.1: no MX but an address record still takes mail ("implicit MX").
                if (answer != Answer.ABSENT || System.currentTimeMillis() > deadline) {
                    return true;
                }
            }
            return false;
        } catch (NamingException e) {
            return true;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException ignored) {
                    // nothing to flush
                }
            }
        }
    }

    private enum Answer { FOUND, ABSENT, UNKNOWN }

    private static Answer lookup(DirContext ctx, String domain, String type) {
        try {
            Attribute attr = ctx.getAttributes(domain, new String[]{type}).get(type);
            return attr != null && attr.size() > 0 ? Answer.FOUND : Answer.ABSENT;
        } catch (NameNotFoundException e) {
            return Answer.ABSENT; // authoritative: the domain doesn't exist
        } catch (NamingException e) {
            return Answer.UNKNOWN;
        }
    }

    private static Set<String> readList(String resource) {
        Set<String> entries = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ClassPathResource(resource).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String entry = line.trim().toLowerCase(Locale.ROOT);
                if (!entry.isEmpty() && !entry.startsWith("#")) {
                    entries.add(entry);
                }
            }
        } catch (Exception e) {
            // A missing list must neither stop the app nor refuse every signup.
            log.warn("Could not read {}: {}", resource, e.toString());
        }
        return Collections.unmodifiableSet(entries);
    }
}
