package io.msh.backend.config;

import io.msh.backend.domain.Member;
import io.msh.backend.domain.RefreshToken;
import io.msh.backend.dto.KeyPair;
import io.msh.backend.dto.MemberDetail;
import io.msh.backend.service.JwtTokenProvider;
import io.msh.backend.service.MemberService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandlerFilter extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberService memberService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request
            , HttpServletResponse response
            , Authentication authentication) throws IOException, ServletException {

        MemberDetail principal = (MemberDetail) authentication.getPrincipal();

        HashMap<String, String> params = new HashMap<>();

        RefreshToken findRefreshToken = jwtTokenProvider.validateRefreshToken(principal.getId());

        if ( findRefreshToken == null ) {
            Member findMember = memberService.getById(principal.getId());
            KeyPair keyPair = jwtTokenProvider.generateKeyPair(findMember);
        } else {

        }


        super.onAuthenticationSuccess(request, response, authentication);
    }
}
