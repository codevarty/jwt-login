package test.jwttest.global.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import test.jwttest.domain.auth.jwt.JwtAuthorizationFilter;
import test.jwttest.domain.auth.jwt.JwtProvider;
import test.jwttest.domain.auth.jwt.LoginFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration configuration;
    private final JwtProvider jwtProvider;

    // 사용자 비밀번호를 캐쉬로 암호화 시키기 위해 사용한다.
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // csrf 변조 공격을 막기 위해 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // form login 비활성화
        http.formLogin(AbstractHttpConfigurer::disable);

        // http basic 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // 서버를 일단 하나로 사용하기 때문에 cors 처리 비활성화
        http.cors(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/h2-console/**").permitAll() // h2 console 접근을 위해 허용
                .requestMatchers("/api", "/login", "/join", "/api/token").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")// Admin 경우에만 접근이 허용이 된다.
                .anyRequest().authenticated());

        // h2-console iframe 을 사용하고 있음.
        // sameOrigin 정책을 허용시켜 iframe 대한 접근 허용
        http.headers(headersConfig -> headersConfig.
                frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        // jwt token의 경우 stateless 정책을 따른다.
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // LoginFilter 를 UsernamePasswordAuthenticationFilter 를 대체한다.
        http.addFilterAt(new LoginFilter(authenticationManager(configuration), jwtProvider), UsernamePasswordAuthenticationFilter.class);

        // JWT 인증 필터는 LoginFilter 전에 실행된다.
        http.addFilterBefore(new JwtAuthorizationFilter(jwtProvider), LoginFilter.class);


        return http.build();
    }
}
