package test.jwttest.domain.member.entity;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter // h2 데잍터 베이스의 경우 user 테이블이 이미 존재하기 때문에 Member로 수정하였다.
public class Member {

  // JWT 학습을 목표로 하기 때문에 엔티티 설정은 최소한으로 한다.
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(length = 50, nullable = false)
  private String username;

  @Column( nullable = false)
  private String password;

  private String role;
}
