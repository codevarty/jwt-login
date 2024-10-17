package test.jwttest.domain.auth.token.repository;

import org.springframework.data.repository.CrudRepository;
import test.jwttest.domain.auth.token.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    Optional<RefreshToken> findByUserId(Long userId);
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
