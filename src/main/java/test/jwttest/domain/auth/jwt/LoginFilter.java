package test.jwttest.domain.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import test.jwttest.domain.auth.custom_user.CustomUserDetails;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;

import java.io.IOException;
import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        log.info("username: {}", username);

        // 현재 로그인 중에 있을 때 401 에러를 반환한다.
        if (jwtProvider.isStoredTokenByUsername(username)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }

    /**
     * 로그인 성공시 JWT 토큰을 발급한다.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        // Member 클래스 추출
        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
        Member member = userDetails.getMember();

        // accessToken refreshToken 생성
        String accessToken = jwtProvider.generateToken(member, Type.ACCESS_TOKEN);
        String refreshToken = jwtProvider.generateToken(member, Type.REFRESH_TOKEN);

        response.addHeader("Authorization", "Bearer " + accessToken);
        response.addHeader("Authorization-refresh", "Bearer " + refreshToken);
    }

    /**
     * 로그인 실패시 401 응답코드를 반환하는 메소드
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        // 로그인 실패시 401 응답코드를 보낸다.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
