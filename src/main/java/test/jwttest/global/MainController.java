package test.jwttest.global;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Main Controller
@RestController
public class MainController {

  @GetMapping("/api")
  public String main() {
    return "Main Controller";
  }
}
