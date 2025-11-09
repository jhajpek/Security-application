package com.example.security.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class RegistrationDto {

    @NotNull
    private String username;

    @NotNull
    private String email;

    @NotNull
    private String rawPassword;

    @NotNull
    private String rawPassword2;

}
