package test.jwttest.domain.auth.token.enums;

import lombok.Getter;

@Getter
public enum Type {
    ACCESS_TOKEN("AT"),
    REFRESH_TOKEN("RT"),
    BLACKLIST("BK");

    private final String value;

    Type(String value) {
        this.value = value;
    }
}
