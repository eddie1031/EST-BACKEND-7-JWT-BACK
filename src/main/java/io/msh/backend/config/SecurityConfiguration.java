package io.msh.backend.config;

import io.msh.backend.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final MemberService memberService;
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
                .build();
    }

}
