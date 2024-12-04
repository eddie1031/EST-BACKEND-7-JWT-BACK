package io.msh.backend.dto;

import io.msh.backend.domain.Member;
import lombok.*;
import lombok.experimental.Accessors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
@Accessors(chain = true)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MemberDetail implements OAuth2User {

    @Setter
    private Long id;

    private String name;
    private String email;

    @Setter
    private String role;

    private Map<String, Object> attributes;

    public static MemberDetail from(Member member) {

        MemberDetail memberDetail = new MemberDetail();

        memberDetail.id = member.getId();
        memberDetail.email = member.getEmail();
        memberDetail.name = member.getUsername();
        memberDetail.role = member.getRole();

        return memberDetail;
    }

    @Builder
    public MemberDetail(String name, String email, Map<String, Object> attributes) {
        this.name = name;
        this.email = email;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getName() {
        return name;
    }
}
