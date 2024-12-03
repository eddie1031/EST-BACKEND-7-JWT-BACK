package io.msh.backend.service;

import io.msh.backend.dto.MemberDetail;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class MemberDetailsFactory {

    public static MemberDetail memberDetail(String provider, OAuth2User oAuth2User) {

        // 사용자 정보(Resource)가 포함되어있음
        Map<String, Object> attributes = oAuth2User.getAttributes();

        switch (provider) {
            case "GOOGLE" -> {
                return MemberDetail.builder()
                        .name(attributes.get("name").toString())
                        .email(attributes.get("email").toString())
                        .attributes(attributes)
                        .build();
            }
            case "KAKAO" -> {
                // properties
                Map<String, String> properties = (Map<String, String>) attributes.get("properties");
                return MemberDetail.builder()
                        .name(properties.get("nickname"))
                        .email(attributes.get("id").toString() + "@kakao.com")
                        .attributes(attributes)
                        .build();
            }
            case "NAVER" -> {
                // response
                Map<String, String> properties = (Map<String, String>) attributes.get("response");
                return MemberDetail.builder()
                        .name(properties.get("name"))
                        .email(properties.get("email"))
                        .attributes(attributes)
                        .build();
            }
            default -> throw new IllegalStateException("Unknown provider = " + provider);
        }

    }


}
