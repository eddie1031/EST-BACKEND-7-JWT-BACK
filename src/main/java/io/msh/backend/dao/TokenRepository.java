package io.msh.backend.dao;

import io.msh.backend.domain.Member;
import io.msh.backend.domain.RefreshToken;

import java.util.Optional;

public interface TokenRepository {
    RefreshToken save(Member member, String token);
    Optional<RefreshToken> findValidRefTokenByToken(String token);
    Optional<RefreshToken> findValidRefTokenByMemberId(Long memberId);
    RefreshToken appendBlackList(RefreshToken token);
}
