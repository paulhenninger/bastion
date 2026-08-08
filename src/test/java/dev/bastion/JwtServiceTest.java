package dev.bastion;

import dev.bastion.config.AppProperties;
import dev.bastion.security.JwtService;
import dev.bastion.user.Role;
import dev.bastion.user.User;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String GOOD_SECRET =
            Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes());

    private static AppProperties props(String secret) {
        return new AppProperties(secret, 15, 30, "http://localhost:5173",
                "test@bastion.local", 24, 30);
    }

    private static User user(long id) throws Exception {
        User user = new User();
        user.setEmail("a@example.com");
        user.setRole(Role.USER);
        Field idField = User.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(user, id);
        return user;
    }

    @Test
    void roundTripsAValidToken() throws Exception {
        JwtService service = new JwtService(props(GOOD_SECRET));
        String token = service.issueAccessToken(user(42L));
        assertThat(service.validate(token)).contains(42L);
    }

    @Test
    void rejectsAGarbageToken() {
        JwtService service = new JwtService(props(GOOD_SECRET));
        assertThat(service.validate("not.a.token")).isEmpty();
    }

    @Test
    void rejectsATokenSignedWithADifferentKey() throws Exception {
        String otherSecret = Base64.getEncoder()
                .encodeToString("ffffffffffffffffffffffffffffffff".getBytes());
        String token = new JwtService(props(otherSecret)).issueAccessToken(user(42L));
        assertThat(new JwtService(props(GOOD_SECRET)).validate(token)).isEmpty();
    }

    @Test
    void refusesToStartWithoutASecret() {
        assertThatThrownBy(() -> new JwtService(props("")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_SECRET is required");
    }

    @Test
    void refusesAShortSecret() {
        String shortSecret = Base64.getEncoder().encodeToString("too-short".getBytes());
        assertThatThrownBy(() -> new JwtService(props(shortSecret)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256 bits");
    }

    @Test
    void refusesANonBase64Secret() {
        assertThatThrownBy(() -> new JwtService(props("!!!not-base64!!!")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("base64");
    }
}
