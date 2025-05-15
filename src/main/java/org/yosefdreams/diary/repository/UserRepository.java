package org.yosefdreams.diary.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.yosefdreams.diary.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByEmail(String email);

  Optional<User> findByUsernameOrEmail(String username, String email);

  Optional<User> findByUsername(String username);

  Optional<User> findByResetToken(String hashedResetToken);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
