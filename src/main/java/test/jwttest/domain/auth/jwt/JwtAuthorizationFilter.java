package test.jwttest.domain.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import test.jwttest.domain.auth.token.enums.Type;

import java.io.IOException;

/**
 * OncePerRequestFilter 의 경우 요청당 한 번만 이 필터가 적용이 된다.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private static final String HEADER_STRING = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authenticationHeader = request.getHeader(HEADER_STRING);

        String token = getAccessToken(authenticationHeader);

        log.info("token : {}", token);


        // 가져온 토큰이 유효한지 확인하고, 유 효한 경우에는 인증 정보 설정
        if (token != null && jwtProvider.validToken(token)) {
            // black list에 토큰이 없어야 하며 해당 이름의 유저의 액세스 토큰의 값이 일치해야 한다.
            if (!jwtProvider.isStoredBlackListToken(token) && jwtProvider.isStoredToken(token, Type.ACCESS_TOKEN)) {
                Authentication authentication = jwtProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().print("유효하지 않는 토큰입니다.");
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }
        return null;
    }
}
