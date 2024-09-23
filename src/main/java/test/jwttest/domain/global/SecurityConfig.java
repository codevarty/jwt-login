package test.jwttest.domain.global;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  // 사용자 비밀번호를 캐쉬로 암호화 시키기 위해 사용한다.
  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
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
        .requestMatchers("/", "/login", "/join").permitAll()
        .requestMatchers("/admin").hasRole("ADMIN")// Admin 경우에만 접근이 허용이 된다.
        .anyRequest().authenticated());

    // h2-console iframe 을 사용하고 있음.
    // sameOrigin 정책을 허용시켜 iframe 대한 접근 허용
    http.headers(headersConfig -> headersConfig.
        frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

    // jwt token의 경우 stateless 정책을 따른다.
    http.sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    return http.build();
  }
}
