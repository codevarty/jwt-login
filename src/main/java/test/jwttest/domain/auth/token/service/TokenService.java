package test.jwttest.domain.auth.token.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import test.jwttest.domain.auth.jwt.JwtProvider;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.service.MemberService;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;
    private final MemberService memberService;

    public String createNewAccessToken(String refreshToken) {

        if (!jwtProvider.validToken(refreshToken)) {
            throw new IllegalArgumentException("Unexpected token");
        }

        Long userId = refreshTokenService.findByToken(refreshToken)
                .getUserId();

        Member member = memberService.findByUserId(userId);

        return jwtProvider.generateToken(member, Duration.ofHours(2));
    }
}
