package test.jwttest.domain.auth.token.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import test.jwttest.domain.auth.jwt.JwtFactory;
import test.jwttest.domain.auth.jwt.JwtProperties;
import test.jwttest.domain.auth.token.dto.CreateAccessTokenRequest;
import test.jwttest.domain.auth.token.enums.Type;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.repository.MemberRepository;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TokenControllerTest {
    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    JwtProperties jwtProperties;

    @Autowired
    MemberRepository memberRepository;

    @Autowired
    RedisTemplate<String, String> redisTemplate;

    @BeforeEach
    public void mockMvcSetup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .build();
        memberRepository.deleteAll();
    }

    @DisplayName("createNewAccessToken: 새로운 접근 토큰 생성")
    @Test
    void createNewAccessToken() throws Exception {
        // given
        final String URL = "/api/token";

        Member testMember = memberRepository.save(Member.builder()
                .username("test")
                .password("test")
                .role("ROLE_USER")
                .build());

        String refreshToken = JwtFactory.builder()
                .claims(Map.of("id", testMember.getId()))
                .build()
                .createToken(jwtProperties);

        String key = Type.REFRESH_TOKEN.getValue() + testMember.getUsername();
        redisTemplate.opsForValue().set(key, refreshToken, 3000L, TimeUnit.MILLISECONDS);

        CreateAccessTokenRequest request = new CreateAccessTokenRequest();
        request.setRefreshToken(refreshToken);
        final String requestBody = objectMapper.writeValueAsString(request);

        // when
        ResultActions resultActions = mockMvc.perform(post(URL)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(requestBody));

        // then
        resultActions
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }
}