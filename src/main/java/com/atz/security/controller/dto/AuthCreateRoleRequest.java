package com.atz.security.controller.dto;

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
public record AuthCreateRoleRequest(
        @Size(max = 2, message = "El usurio no puede tener mas de 2 roles") List<String> rolesName) {
}
