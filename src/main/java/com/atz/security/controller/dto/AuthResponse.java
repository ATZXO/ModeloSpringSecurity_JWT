package com.atz.security.controller.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username", "message", "jwtToken", "status"})
public record AuthResponse(
        String username,
        String message,
        String jwtToken,
        boolean status
) {
}
