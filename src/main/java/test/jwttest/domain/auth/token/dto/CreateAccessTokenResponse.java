package test.jwttest.domain.auth.token.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CreateAccessTokenResponse {
    private String accessToken;
}
