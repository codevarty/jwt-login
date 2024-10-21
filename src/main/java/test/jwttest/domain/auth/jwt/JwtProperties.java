package test.jwttest.domain.auth.jwt;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Setter
@Getter
@Component
@ConfigurationProperties("jwt")
public class JwtProperties {
  private String issuer;
  private String secret;
  private Long accessExpiration;
  private Long refreshExpiration;

  /**
   * 인증키 반환 메소드
   *
   * @return SecretKey
   */
  public SecretKey getSecretKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
  }
}
