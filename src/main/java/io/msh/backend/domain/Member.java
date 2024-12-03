package io.msh.backend.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

    @Id
    @Column(name = "member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String provider;

    private String email;

    @Setter
    private String role = "USER";

    private LocalDateTime signedAt = LocalDateTime.now();

    @Builder
    public Member(String username, String provider, String email) {
        this.username = username;
        this.provider = provider;
        this.email = email;
    }
}
