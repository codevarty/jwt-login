package test.jwttest.domain.auth.token.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import test.jwttest.domain.auth.token.entity.RefreshToken;
import test.jwttest.domain.auth.token.repository.RefreshTokenRepository;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByRefreshToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Unexpected token"));
    }
}
