package io.msh.backend.service;

import io.msh.backend.dao.MemberRepository;
import io.msh.backend.domain.Member;
import io.msh.backend.dto.MemberDetail;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;
import java.util.Optional;

// 회원가입
// OAuth2.0 인증 -> 가입
@Service
@Transactional
@RequiredArgsConstructor
public class MemberService extends DefaultOAuth2UserService {

    private final MemberRepository repository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId().toUpperCase();

        MemberDetail memberDetail = MemberDetailsFactory.memberDetail(provider, oAuth2User);

        Optional<Member> memberOptional = repository.findByEmail(memberDetail.getEmail());

        Member findMember = memberOptional.orElseGet(
                () -> {
                    Member member = Member.builder()
                            .email(memberDetail.getEmail())
                            .username(memberDetail.getName())
                            .provider(provider)
                            .build();
                    return repository.save(member);
                }
        );

        if ( findMember.getProvider().equals(provider) ) {
//            return memberDetail;
            return memberDetail.setId(findMember.getId()).setRole(findMember.getRole());
        } else {
            throw new RuntimeException();
        }

    }

    public Optional<Member> findById(Long id) {
        return repository.findById(id);
    }

    public Member getById(Long id) {
        return findById(id).orElseThrow(
                () -> new NoSuchElementException("Member not found")
        );
    }

    public MemberDetail loadMemberDetailById(Long id) {
        Member findMember = getById(id);
        return MemberDetail.from(findMember);
    }


}















