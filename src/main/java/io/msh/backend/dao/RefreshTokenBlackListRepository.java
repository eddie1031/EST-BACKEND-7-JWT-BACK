package io.msh.backend.dao;

import io.msh.backend.domain.RefreshToken;
import io.msh.backend.domain.RefreshTokenBlackList;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenBlackListRepository extends JpaRepository<RefreshTokenBlackList, Long> {
    boolean existsByRefreshToken(RefreshToken refreshToken);
}
