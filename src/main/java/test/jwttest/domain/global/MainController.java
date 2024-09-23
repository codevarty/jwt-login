package test.jwttest.domain.global;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Main Controller
@RestController
public class MainController {

  @GetMapping("/")
  public String main() {
    return "Main Controller";
  }
}
