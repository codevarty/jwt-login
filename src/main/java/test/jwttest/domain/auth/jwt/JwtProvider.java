package test.jwttest.domain.auth.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Component
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.access.expiration}")
    private Long accessExpiration;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    @Value("${jwt.refresh.expiration}")
    private Long refreshExpiration;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String BEARER = "Bearer ";

    /**
     * 인증키 반환 메소드
     *
     * @return SecretKey
     */
    private SecretKey getSignKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    /**
     * accessToken 생성 메소드
     *
     * @param username
     * @param role
     * @return accessToken
     */
    public String generateAccessToken(String username, String role) {
        return Jwts.builder()
                .subject(ACCESS_TOKEN_SUBJECT)
                .expiration(new Date(System.currentTimeMillis() + accessExpiration))
                .claim("username", username)
                .claim("role", role)
                .signWith(getSignKey())
                .compact();
    }

    /**
     * refreshToken 생성 메소드
     *
     * @return refreshToken
     */
    public String generateRefreshToken() {
        return Jwts.builder()
                .subject(REFRESH_TOKEN_SUBJECT)
                .expiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getSignKey())
                .compact();
    }

    /**
     * header 에서 accessToken 추출 메소드
     *
     * @param request
     * @return extractAccessToken
     */
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader)).filter(
                access -> access.startsWith(BEARER)
        ).map(access -> access.replace(BEARER, ""));
    }

    /**
     * header 에서 refreshToken 추출 메소드
     *
     * @param request
     * @return extractRefreshToken
     */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader)).filter(
                refresh -> refresh.startsWith(BEARER)
        ).map(refresh -> refresh.replace(BEARER, ""));
    }

    /**
     * JWT 검증 메소드
     *
     * @param token
     * @return isValidate
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    /**
     * 토큰에서 username claim 추출 메소드
     *
     * @param token
     * @return username claim
     */
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    /**
     * 토큰에서 role claim 추출 메소드
     *
     * @param token
     * @return role claim
     */
    public String getRole(String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

}
