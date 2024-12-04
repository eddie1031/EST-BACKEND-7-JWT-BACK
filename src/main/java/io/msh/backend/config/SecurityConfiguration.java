package io.msh.backend.config;

import io.msh.backend.service.MemberService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final MemberService memberService;
    private final JwtTokenFilter jwtTokenFilter;
    private final OAuth2SuccessHandlerFilter oauth2SuccessHandlerFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
//                .oauth2Login(Customizer.withDefaults())
                .oauth2Login(
                        oauth2 -> oauth2.successHandler(oauth2SuccessHandlerFilter)
                                .userInfoEndpoint(end -> end.userService(memberService))
                )
                .authorizeHttpRequests(
                        auth -> {
                            auth.requestMatchers("/members/**")
                                    .hasAnyAuthority("ADMIN", "MEMBER")
                                .requestMatchers("/admins/**")
                                    .hasAnyAuthority("ADMIN")
                                .anyRequest().authenticated();
                        }
                )
                .exceptionHandling(
                        exception -> exception.authenticationEntryPoint(
                                (req, resp, ex) -> {
                                    resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                    resp.setContentType("application/json");
                                    resp.getWriter().write("{\"error\": \"Unauthorized\"}");
                                }
                        )

                )
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}
