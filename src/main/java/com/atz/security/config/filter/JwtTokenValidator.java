package com.atz.security.config.filter;

import com.atz.security.util.JwtUtils;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

@RequiredArgsConstructor
public class JwtTokenValidator extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION); //Obtiene el header Authorization de la peticion

        if(header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); //Extrae el token sin el prefijo "Bearer "

            DecodedJWT decodedJWT = jwtUtils.validateToken(token); //Valida el token

            //Si el token es valido, extrae la informacion que necesites
            String username = jwtUtils.getUsernameFromToken(decodedJWT); //Extrae el nombre de usuario del token
            String StringAuthorities = jwtUtils.getClaim(decodedJWT, "authorities").asString(); //Extrae los permisos del token

            Collection <? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(StringAuthorities); //Convierte los permisos separados por coma a una coleccion de GrantedAuthority

            SecurityContext context = SecurityContextHolder.getContext(); //Obtiene el contexto de seguridad actual

            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities); //Crea un objeto de autenticacion con el nombre de usuario y los permisos
            context.setAuthentication(authentication); //Establece la autenticacion en el contexto de seguridad
            SecurityContextHolder.setContext(context); //Actualiza el contexto de seguridad
        }
        filterChain.doFilter(request, response);
    }
}
