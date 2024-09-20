package test.jwttest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // csrf 변조 공격을 막기 위해 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // 서버를 일단 하나로 사용하기 때문에 cors 처리 비활성화
        http.cors(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(
                        new AntPathRequestMatcher("/h2-console/**")).permitAll()
                .requestMatchers(
                        new AntPathRequestMatcher("/api/test")).permitAll());

        // h2-console iframe 을 사용하고 있음.
        // sameOrigin 정책을 허용시켜 iframe 대한 접근 허용
        http.headers(headersConfig -> headersConfig.
                frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        return http.build();
    }
}
