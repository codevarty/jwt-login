package test.jwttest.domain.auth.token.entity;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash("refreshToken")
public class RefreshToken {

    @Id
    private String refreshToken;
    private Long userId;

    public RefreshToken(String refreshToken, Long userId) {
        this.refreshToken = refreshToken;
        this.userId = userId;
    }
}
