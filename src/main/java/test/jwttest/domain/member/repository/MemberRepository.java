package test.jwttest.domain.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import test.jwttest.domain.member.entity.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Boolean> existsByUsername(String username);

    Optional<Member> findByUsername(String username);
}
