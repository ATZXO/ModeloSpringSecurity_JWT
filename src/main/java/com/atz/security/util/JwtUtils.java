package com.atz.security.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${security.jwt.key.private}")
    private String keyPrivate;
    @Value("${security.jwt.user.generation}")
    private String userGenerator;

    public String createToken(Authentication authentication) {
        Algorithm algorithm = Algorithm.HMAC256(keyPrivate);

        String username = authentication.getPrincipal().toString();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); //Cada permiso separado por coma

        String token = JWT.create()
                .withIssuer(userGenerator) //El emisor del token (es quien lo genera)
                .withSubject(username) //El subject es el usuario que recibe el token
                .withClaim("authorities", authorities) //Los permisos del usuario
                .withIssuedAt(new Date()) //Fecha de creacion del token
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000)) //El token dura 1 hora
                .withJWTId(UUID.randomUUID().toString()) //Un id unico para el token
                .withNotBefore(new Date(System.currentTimeMillis())) //El token es valido a partir de ese momento
                .sign(algorithm);

        return token;
    }

    public DecodedJWT validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(keyPrivate); //Algoritmo para verificar el token

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build(); //Crea el verificador de tokens con el algoritmo y el emisor

            DecodedJWT decodedJWT = verifier.verify(token); //Verifica el token y obtiene el DecodedJWT si es valido

            return decodedJWT;
        }catch (JWTVerificationException exception){
            throw new JWTVerificationException("Token no valido o ha expirado");
        }
    }

    public String getUsernameFromToken(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject();
    }

    public Claim getClaim(DecodedJWT decodedJWT, String claimName) {
        return decodedJWT.getClaim(claimName);
    }

    public Map<String, Claim> getAllClaims(DecodedJWT decodedJWT) {
        return decodedJWT.getClaims();
    }

}
