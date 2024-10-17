package test.jwttest.domain.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import test.jwttest.domain.member.entity.Member;

import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtProvider {
  private final JwtProperties jwtProperties;

  /**
   * 토큰 생성 메소드
   *
   * @param member    멤버 클래스
   * @param expiredAt 만료기간
   * @return Jwt token
   */
  public String generateToken(Member member, Duration expiredAt) {
    Date now = new Date();

    return makeToken(new Date(now.getTime() + expiredAt.toMillis()), member);
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
        .subject("Authentication")
        .claim("username", member.getUsername())
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
   * @param token 문자열 메소드
   * @return Authentication
   */
  public Authentication getAuthentication(String token) {
    Claims claims = getClaims(token);
    Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));
    return new UsernamePasswordAuthenticationToken(new User(claims.getSubject(), "", authorities), token, authorities);
  }


  /**
   * 유저네임 반환
   *
   * @param token 문자열 토큰
   * @return username
   */
  public String getUsername(String token) {
    Claims claims = getClaims(token);
    return claims.get("username", String.class);
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
