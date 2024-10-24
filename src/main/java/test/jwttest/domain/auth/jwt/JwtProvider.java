package test.jwttest.domain.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;

import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtProvider {
    private final JwtProperties jwtProperties;
    private final RedisTemplate<String, String> redisTemplate;


    /**
     * 토큰 생성 메소드
     *
     * @param member    멤버 클래스
     * @param type      토큰의 타입 설정 (AccessToken, RefreshToken)
     * @return Jwt token
     */
    public String generateToken(Member member, Type type) {
        Date now = new Date();
        Date expiry;

        if (type.equals(Type.ACCESS_TOKEN)) {
            expiry = new Date(now.getTime() + jwtProperties.getAccessExpiration());
        } else if (type.equals(Type.REFRESH_TOKEN)) {
            expiry = new Date(now.getTime() + jwtProperties.getRefreshExpiration());
        } else {
            throw new IllegalArgumentException("unsupported type: " + type);
        }

        String token = makeToken(expiry, member);

        // key 생성
        String key = type.getValue() + member.getUsername();

        // redis 저장
        redisTemplate.opsForValue()
                .set(key, token, getExpiration(token), TimeUnit.MILLISECONDS);

        return token;
    }

    /**
     * 현재 유저네임으로 접속중인지 확인하는 메소드
     *
     * @param username username
     * @return isStored accessToken
     */
    public boolean isStoredTokenByUsername(String username) {

        String key = Type.ACCESS_TOKEN.getValue() + username;

        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }


    public void deleteToken(String username, Type type) {
        redisTemplate.delete(type.getValue() + username);
    }

    /**
     * 토큰을 블랙리스트에 추가한다.
     *
     * @param token 문자열 토큰
     */
    public void addBlackListToken(String token) {
        String key = Type.ACCESS_TOKEN.getValue() + getUsername(token);
        // 해당 키를 가지는 AccessToken 이 저장되어 있을시 먼저 지운 다음에 추가를 진행한다.
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))) {
            redisTemplate.delete(key);
        }

        // black list 에 추가된 토큰은 사용이 불가능하다.
        redisTemplate.opsForValue()
                .set(token, "useless", getExpiration(token), TimeUnit.MILLISECONDS);
    }

    /**
     * 토큰이 블랙리스트에 저장되어 있는지 확인하는 메소드
     *
     * @param token 문자열 토큰
     * @return isStoredToken
     */
    public boolean isStoredBlackListToken(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }

    /**
     * 내부 토큰 생성 메소드
     *
     * @param expiry 만료기간
     * @param member 멤버 클래스
     * @return Jwt token
     */
    private String makeToken(Date expiry, Member member) {
        Date now = new Date();

        return Jwts.builder()
                .header()
                .add("type", "JWT")
                .and()
                .issuer(jwtProperties.getIssuer())
                .issuedAt(now) // 발급일자 : 현재 시간
                .expiration(expiry) // 만료 기간
                .subject(member.getUsername())
                .claim("id", member.getId())
                .signWith(jwtProperties.getSecretKey())
                .compact();
    }

    /**
     * Jwt 검증 메소드
     *
     * @param token 문자열 토큰
     * @return isValidate
     */
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(jwtProperties.getSecretKey())
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (JwtException e) { // 복호화 하는 도중 유효하지 않는 토큰인 경우 false 리턴
            log.error(e.getMessage());
            return false;
        }
    }

    /**
     * 토큰 기반으로 인증 정보를 가져오는 메소드
     *
     * @param token 문자열 토큰
     * @return Authentication
     */
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));
        return new UsernamePasswordAuthenticationToken(new User(claims.getSubject(), "", authorities), token, authorities);
    }

    /**
     * 토큰 생존 시간을 반환하는 메소드
     *
     * @param token 문자열 토큰
     * @return 만료시간까지 남은 시간 Live Time
     */
    public Long getExpiration(String token) {
        Claims claims = getClaims(token);
        Date now = new Date();
        return claims.getExpiration().getTime() - now.getTime();
    }


    /**
     * 유저아이디를 반환
     *
     * @param token 문자열 토큰
     * @return userId
     */
    public Long getUserId(String token) {
        Claims claims = getClaims(token);
        return claims.get("id", Long.class);
    }

    /**
     * 유저 이름을 반환
     * @param token 문자열 토큰
     * @return username
     */
    public String getUsername(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    /**
     * Claims 반환 메소드
     *
     * @param token - 문자열 토큰
     * @return Claims
     */
    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtProperties.getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
