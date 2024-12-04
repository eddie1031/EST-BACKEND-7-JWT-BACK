package io.msh.backend.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/members")
public class MemberApiController {

    @GetMapping("/greet")
    public String greet() {
        return "Hello! Member!";
    }

}