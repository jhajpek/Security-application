package com.example.security.service;

import com.example.security.dto.LoginDto;
import com.example.security.dto.RegistrationDto;
import com.example.security.entity.User;
import com.example.security.repo.UserRepository;
import com.example.security.repo.UserRepository2;
import com.example.security.util.UserManagementException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@AllArgsConstructor
public class UserService {
    private static final String EMAIL_REGEX = "^(?![.])(?!.*[.]{2})[A-Za-z0-9.]+(?<![.])@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    private static final String PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&/\\\\#_+=-])[A-Za-z\\d@$!%*?&/\\\\#_+=-]{8,}$";
    private static final int LOCK_MINUTES = 5;

    private final UserRepository userRepository;
    private final UserRepository2 userRepository2;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public User registerUser(RegistrationDto registrationDto) {
        String username = registrationDto.getUsername();
        if (username.isEmpty() || username.length() > 20) {
            throw new UserManagementException("Korisničko ime treba biti minimalno duljine 1, a maksimalno 20.");
        }

        String email = registrationDto.getEmail();
        if (email.isEmpty() || email.length() > 100) {
            throw new UserManagementException("E-mail adresa treba biti minimalno duljine 8, a maksimalno 100.");
        }

        if (isEmailInvalid(email)) {
            throw new UserManagementException("E-mail adresa mora odgovarati regularnom izrazu: " + EMAIL_REGEX);
        }

        Optional<User> existingUser = userRepository.findByUsernameOrEmail(username, email);
        if (existingUser.isPresent()) {
            throw new UserManagementException("Već ste registrirani? Račun s navedenim korisničkim imenom ili e-mailom već postoji.");
        }

        String rawPassword = registrationDto.getRawPassword();
        if (isPasswordWeak(rawPassword)) {
            throw new UserManagementException("Lozinka mora biti minimalno 8 dugacka, imati malo slovo, veliko slovo, broj i specijalni znak, odnosno odgovarati regularnom izrazu: " + EMAIL_REGEX);
        }

        String rawPassword2 = registrationDto.getRawPassword2();
        if (!rawPassword.equals(rawPassword2)) {
            throw new UserManagementException("Upisana lozinka se ne podudara s ponovljenom lozinkom.");
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setVerified(true);
        return userRepository.save(user);
    }

    public void verifyUser(UUID userId) {
        Optional<User> potentialUser = userRepository.findById(userId);
        if (potentialUser.isEmpty()) {
            throw new UserManagementException("Jeste li sigurni da ste obavili registraciju?");
        }

        User existingUser = potentialUser.get();
        if (existingUser.isVerified()) {
            throw new UserManagementException("Vaš račun je već verificiran.");
        }

        existingUser.setVerified(true);
        userRepository.save(existingUser);
    }

    public String loginUser(LoginDto loginDto) {
        String usernameOrEmail = loginDto.getUsernameOrEmail();
        String rawPassword = loginDto.getRawPassword();
        boolean sqlInjectionFlag = loginDto.isSqlInjectionFlag();
        boolean brokenAuthFlag = loginDto.isBrokenAuthFlag();

        Optional<User> potentialUser = sqlInjectionFlag ?
                userRepository2.findByUsernameOrEmail(usernameOrEmail) :
                userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail);
        if (potentialUser.isEmpty()) {
            if (brokenAuthFlag) {
                throw new UserManagementException("Korisnik s ovakvim korisničkim imenom ne postoji.");
            } else {
                throw new UserManagementException("Krivo korisničko ime, e-mail ili lozinka");
            }
        }

        User user = potentialUser.get();

        if (!user.isVerified()) {
            throw new UserManagementException("Račun nije verificiran. Provjerite email.");
        }

        Instant now = Instant.now();
        if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
            long secondsLeft = user.getLockedUntil().getEpochSecond() - now.getEpochSecond();
            throw new UserManagementException("Račun je privremeno zaključan. Pokušajte ponovno za " + secondsLeft + " sekundi.");
        }

        if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            user.setFailedConsecutiveAttempts(0);
            user.setLockedUntil(null);
            User loggedInUser = userRepository.save(user);
            return jwtService.generateToken(loggedInUser);
        } else {
            if (!brokenAuthFlag) {
                int failedAttempts = user.getFailedConsecutiveAttempts() + 1;
                user.setFailedConsecutiveAttempts(failedAttempts);

                if (failedAttempts > 0 && failedAttempts % 5 == 0) {
                    user.setLockedUntil(now.plusSeconds(LOCK_MINUTES * 60L));
                }

                userRepository.save(user);
            }

            if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
                throw new UserManagementException("Previše neuspjelih pokušaja. Račun je zaključan na " + LOCK_MINUTES + " minuta.");
            } else if (brokenAuthFlag) {
                throw new UserManagementException("Kriva lozinka");
            } else {
                throw new UserManagementException("Krivo korisničko ime, e-mail ili lozinka");
            }
        }
    }

    private boolean isEmailInvalid(String email) {
        return !Pattern.matches(EMAIL_REGEX, email);
    }

    private boolean isPasswordWeak(String password) {
        return !Pattern.matches(PASSWORD_REGEX, password);
    }

}
