package com.example.security.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LoginDto {

    @NotNull
    private String usernameOrEmail;

    @NotNull
    private String rawPassword;

    @NotNull
    private boolean sqlInjectionFlag;

    @NotNull
    private boolean brokenAuthFlag;

}
