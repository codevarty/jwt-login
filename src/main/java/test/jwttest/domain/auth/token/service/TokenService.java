package test.jwttest.domain.auth.token.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import test.jwttest.domain.auth.jwt.JwtProvider;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.service.MemberService;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, String> redisTemplate;
    private final MemberService memberService;


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

        Member member = memberService.findByUserId(userId);

        return jwtProvider.generateToken(member, Type.ACCESS_TOKEN);
    }
}
