package test.jwttest.domain.admin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

  // 어드민 테스트 컨트롤러
  @GetMapping("/admin")
  public String admin() {
    return "admin";
  }
}
