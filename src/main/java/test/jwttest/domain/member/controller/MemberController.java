package test.jwttest.domain.member.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import test.jwttest.domain.member.dto.JoinDTO;
import test.jwttest.domain.member.service.MemberService;

@RestController
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/join")
    public String join(@RequestBody JoinDTO joinDTO) {
        Long joined = memberService.join(joinDTO);

        if (joined != null) {
            return "ok";
        }

        return "username already exists";
    }
}
