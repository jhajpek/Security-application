package com.example.security.repo;

import com.example.security.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Repository
@AllArgsConstructor
public class UserRepository2 {
    private JdbcTemplate jdbcTemplate;

    public Optional<User> findByUsernameOrEmail(String input) {
        String sql = "SELECT * FROM app_user WHERE username = '" + input + "' OR email = '" + input + "' LIMIT 1";
        List<Map<String, Object>> potentialUsers = jdbcTemplate.queryForList(sql);
        if (potentialUsers.isEmpty()) {
            return Optional.empty();
        }
        User user = new User();
        Map<String, Object> attributes = potentialUsers.get(0);
        user.setId((UUID) attributes.get("id"));
        user.setUsername((String) attributes.get("username"));
        user.setEmail((String) attributes.get("email"));
        user.setPasswordHash((String) attributes.get("password_hash"));
        user.setFailedConsecutiveAttempts((Integer) attributes.get("failed_consecutive_attempts"));
        var timestamp = ((java.sql.Timestamp) attributes.get("locked_until"));
        user.setLockedUntil(timestamp == null ? null : timestamp.toInstant());
        user.setVerified((Boolean) attributes.get("is_verified"));
        return Optional.of(user);
    }
}
