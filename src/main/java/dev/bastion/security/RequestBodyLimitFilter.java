package dev.bastion.security;

import dev.bastion.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Caps how large a request body the app will read (default 64 KiB — the largest
 * legitimate body here is a passkey attestation of a few KiB).
 *
 * <p>Tomcat's own limit covers form posts only. Jackson reads a whole JSON body into
 * the heap <em>before</em> any {@code @Size} constraint runs, so without this a
 * handful of concurrent anonymous multi-hundred-megabyte posts to {@code /auth/login}
 * would exhaust the heap — no account and no rate limit in the way.
 *
 * <p>A declared {@code Content-Length} over the limit is refused with 413 before a
 * byte is read. A chunked body declares nothing, so the stream itself is counted and
 * fails once the limit is passed (the handler then answers 400).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RequestBodyLimitFilter extends OncePerRequestFilter {

    private final long limit;

    public RequestBodyLimitFilter(AppProperties props) {
        this.limit = props.security().maxRequestBytes();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (request.getContentLengthLong() > limit) {
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"message\":\"Request body too large\"}");
            return;
        }
        chain.doFilter(new Limited(request, limit), response);
    }

    private static final class Limited extends HttpServletRequestWrapper {
        private final long limit;
        private ServletInputStream stream;

        Limited(HttpServletRequest request, long limit) {
            super(request);
            this.limit = limit;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new Counting(super.getInputStream(), limit);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class Counting extends ServletInputStream {
        private final ServletInputStream in;
        private final long limit;
        private long read;

        Counting(ServletInputStream in, long limit) {
            this.in = in;
            this.limit = limit;
        }

        private int count(int n) throws IOException {
            if (n > 0) {
                read += n;
                if (read > limit) {
                    throw new IOException("Request body exceeds " + limit + " bytes");
                }
            }
            return n;
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b >= 0) {
                count(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return count(in.read(b, off, len));
        }

        @Override
        public boolean isFinished() {
            return in.isFinished();
        }

        @Override
        public boolean isReady() {
            return in.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            in.setReadListener(listener);
        }
    }
}
