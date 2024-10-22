package test.jwttest.domain.auth.jwt;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.repository.MemberRepository;

import java.time.Duration;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
class JwtProviderTest {
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private JwtProperties jwtProperties;

    @DisplayName("generate token: 유저 정보와 만료 기간을 전달해 토큰 생성")
    @Test
    void generateToken() {

        // given
        Member member = memberRepository.save(Member.builder()
                .username("hello")
                .password("test123!")
                .role("ROLE_USER")
                .build());

        // when
        String token = jwtProvider.generateToken(member, Type.ACCESS_TOKEN);

        //then
        Long userId = Jwts.parser()
                .verifyWith(jwtProperties.getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("id", Long.class);

        assertThat(userId).isEqualTo(member.getId());
    }

    @DisplayName("validToken(): 만료된 토큰인 떄에 유효성 검증에 실패한다.")
    @Test
    void validTokenInvalidToken() {
        // given
        String token = JwtFactory.builder()
                .expiration(new Date(new Date().getTime() - Duration.ofDays(7).toMillis()))
                .build()
                .createToken(jwtProperties);

        //when
        boolean result = jwtProvider.validToken(token);

        //then
        assertThat(result).isFalse();
    }

    @DisplayName("getAuthentication(): 토큰 기반으로 인증정보를 가져올 수 있다.")
    @Test()
    void getAuthentication() {
        // given
        String username = "test2";
        String token = JwtFactory.builder()
                .subject(username)
                .build()
                .createToken(jwtProperties);

        // when
        Authentication authentication = jwtProvider.getAuthentication(token);

        // then
        assertThat(((UserDetails) authentication.getPrincipal()).getUsername())
                .isEqualTo(username);

    }

    @DisplayName("getUsername(): 토큰으로 유저아이디를 가져 올 수 있다.")
    @Test
    void getUsername() {
        //given
        Long userId = 1L;
        String token = JwtFactory.builder()
                .claims(Map.of("id", userId))
                .build()
                .createToken(jwtProperties);

        // when
        Long userIdByToken = jwtProvider.getUserId(token);

        //then
        assertThat(userIdByToken).isEqualTo(userId);
    }
}