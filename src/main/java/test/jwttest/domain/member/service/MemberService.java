package test.jwttest.domain.member.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import test.jwttest.domain.member.dto.JoinDTO;
import test.jwttest.domain.member.entity.Member;
import test.jwttest.domain.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Long join(JoinDTO joinDTO) {
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        boolean existUser = memberRepository.existsByUsername(username);

        // 유저가 이미 존재하는 경우 에러를 반환한다.
        if (existUser) {
            throw new IllegalArgumentException("Username is already in use");
        }

        Member member = new Member().builder()
            .username(username)
            .password(bCryptPasswordEncoder.encode(password))
            .role("ROLE_USER")
            .build();

        return memberRepository.save(member).getId();
    }

    public Member findByUserId(Long userId) {
        return memberRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Unexpected User"));
    }
}
