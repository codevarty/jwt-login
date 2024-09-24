package test.jwttest.domain.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import test.jwttest.domain.member.entity.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Boolean existsByUsername(String username);
}
