package com.example.security.controller;

import com.example.security.dto.LoginDto;
import com.example.security.dto.RegistrationDto;
import com.example.security.service.MailService;
import com.example.security.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.mail.MailException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

@Controller
public class ViewController {
    private final UserService userService;
    private final MailService mailService;
    private final String expiresAfter;

    public ViewController(UserService userService,
                          MailService mailService,
                          @Value("${jwt.expires-after}") String expiresAfter) {
        this.userService = userService;
        this.mailService = mailService;
        this.expiresAfter = expiresAfter;
    }

    @GetMapping("/")
    public String getHomePage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            model.addAttribute("username", auth.getName());
        }
        if (!model.containsAttribute("login")) {
            model.addAttribute("login", new LoginDto());
        }
        if (!model.containsAttribute("registration")) {
            model.addAttribute("registration", new RegistrationDto());
        }
        return "home";
    }

    @GetMapping("/verify/{userId}")
    public String verifyUser(@PathVariable("userId") UUID userId, Model model) {
        try {
            userService.verifyUser(userId);
            model.addAttribute("errMsg", "Verifikacija uspješna. Sada se možete prijaviti.");
        } catch (Exception e) {
            model.addAttribute("errMsg", e.getMessage());
        }
        return "verification";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute RegistrationDto registrationDto,
                               RedirectAttributes redirectAttributes) {
        try {
            userService.registerUser(registrationDto);
        } catch (MailException e) {
            redirectAttributes.addFlashAttribute("registration", registrationDto);
            redirectAttributes.addFlashAttribute("errMsg", "Servis za slanje maila ne radi trenutno...");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("registration", registrationDto);
            redirectAttributes.addFlashAttribute("errMsg", e.getMessage());
        }
        return "redirect:/";
    }

    @PostMapping("/login")
    public String loginUser(@ModelAttribute LoginDto loginDto,
                            RedirectAttributes redirectAttributes,
                            HttpServletResponse response) {
        try {
            String token = userService.loginUser(loginDto);

            ResponseCookie cookie = ResponseCookie.from("JWT", token)
                    .httpOnly(!loginDto.isBrokenAuthFlag())
                    .secure(true)
                    .sameSite("Strict")
                    .path("/")
                    .maxAge(Integer.parseInt(expiresAfter))
                    .build();

            response.addHeader("Set-Cookie", cookie.toString());
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("login", loginDto);
            redirectAttributes.addFlashAttribute("errMsg", e.getMessage());
        }
        return "redirect:/";
    }

}
