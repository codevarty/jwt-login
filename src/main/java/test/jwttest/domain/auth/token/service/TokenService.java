package test.jwttest.domain.auth.token.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import test.jwttest.domain.auth.jwt.JwtProvider;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.repository.MemberRepository;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, String> redisTemplate;
    private final MemberRepository memberRepository;

    private static final Duration ACCESS_EXPIRATION = Duration.ofHours(2);
    private static final Duration REFRESH_EXPIRATION = Duration.ofDays(14);

    /**
     * AccessToken 만료시 재발급 메소드
     *
     * @param refreshToken 문자열 토큰
     * @return newAccessToken
     */
    public String createNewAccessToken(String refreshToken) {

        if (!jwtProvider.validToken(refreshToken)) {
            throw new IllegalArgumentException("Unexpected token");
        }

        if (Boolean.FALSE.equals(redisTemplate.hasKey(refreshToken))) {
            throw new IllegalArgumentException("Unexpected token");
        }

        Long userId = jwtProvider.getUserId(refreshToken);

        Member member = memberRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Member not found"));

        return jwtProvider.generateToken(member, Duration.ofHours(2));
    }

    public String generateAccessToken(Member member) {
        String accessToken = jwtProvider.generateToken(member, ACCESS_EXPIRATION);
        // 토큰 정보를 Redis 에 저장한다.
        String value = Type.ACCESS_TOKEN.getValue() + member.getId();
        saveToken(accessToken, value, ACCESS_EXPIRATION.toMillis());
        return accessToken;
    }

    public String generateRefreshToken(Member member) {
        String refreshToken = jwtProvider.generateToken(member, REFRESH_EXPIRATION);

        // 토큰 정보를 Redis 에 저장한다.
        String value = Type.REFRESH_TOKEN.getValue() + member.getId();
        saveToken(refreshToken, value, REFRESH_EXPIRATION.toMillis());
        return refreshToken;
    }

    public Boolean isStoredBlackListById(Long memberId) {
        String key = Type.ACCESS_TOKEN.getValue() + memberId;
        return redisTemplate.hasKey(key);
    }


    /**
     * 사용한 토큰은 블랙리스트에 추가하여 저장할 수 없게 한다.
     *
     * @param token 문자열 accessToken 들어온다.
     */
    public void invalidToken(String token) {
        Long userId = jwtProvider.getUserId(token);
        // 해당 키를 가지는 AccessToken 이 저장되어 있을시 먼저 지운 다음에 추가를 진행한다.
        if (Boolean.TRUE.equals(redisTemplate.hasKey(token))) {
            redisTemplate.delete(token);
        }

        String key = Type.ACCESS_TOKEN.getValue() + userId;

        saveToken(key, Type.BLACKLIST.getValue(), jwtProvider.getExpiration(token));
    }

    private void saveToken(String token, String value, Long expiration) {
        redisTemplate.opsForValue()
            .set(token, value, expiration, TimeUnit.MILLISECONDS);
    }
}
