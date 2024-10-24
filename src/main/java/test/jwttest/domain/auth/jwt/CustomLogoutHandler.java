package test.jwttest.domain.auth.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import test.jwttest.domain.auth.token.enums.Type;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler, LogoutSuccessHandler {
    private final JwtProvider jwtProvider;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String token = header.replace("Bearer ", "");
        String username = jwtProvider.getUsername(token);
        jwtProvider.deleteToken(username, Type.REFRESH_TOKEN);
        jwtProvider.addBlackListToken(token);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print("Successfully logged out");
    }
}
