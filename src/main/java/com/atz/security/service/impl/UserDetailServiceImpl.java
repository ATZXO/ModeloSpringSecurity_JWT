package com.atz.security.service.impl;

import com.atz.security.controller.dto.AuthCreateUserRequest;
import com.atz.security.controller.dto.AuthLoginRequest;
import com.atz.security.controller.dto.AuthResponse;
import com.atz.security.entities.RolesEntity;
import com.atz.security.entities.UserEntity;
import com.atz.security.repository.RoleRepository;
import com.atz.security.repository.UserRepository;
import com.atz.security.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username).orElseThrow(()->
                new UsernameNotFoundException("El usuario no existe"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        //Agregar roles al usuario
        userEntity.getRoles().forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        //Agregar permisos al usuario
        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnable(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList);
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username, password); //Autenticar al usuario
        SecurityContextHolder.getContext().setAuthentication(authentication); //Establecer la autenticacion en el contexto de seguridad

        String authToken = jwtUtils.createToken(authentication); //Generar el token JWT

        AuthResponse authResponse = new AuthResponse(username,"Login exitoso", authToken,true); //Crear la respuesta de autenticacion

        return authResponse;
    }

    public Authentication authenticate(String username, String password) {
        UserDetails userDetails = loadUserByUsername(username);

        if(userDetails == null) {
            throw new BadCredentialsException("Credenciales invalidas");
        }

        if (passwordEncoder.matches(password, userDetails.getPassword())) { //Verificar la contraseña
            return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities()); //Retornar la autenticacion con los detalles del usuario
        } else {
            throw new BadCredentialsException("Username o password incorrectos");
        }
    }

    public AuthResponse registerUser(AuthCreateUserRequest authCreateUserRequest){
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String> rolesName = authCreateUserRequest.roleRequest().rolesName();

        Set<RolesEntity> rolesEntitySet = roleRepository.findRolesEntitiesByRoleEnumIn(rolesName).stream().collect(Collectors.toSet()); //Verificar que los roles existan

        if(rolesEntitySet.isEmpty()){
            throw new IllegalArgumentException("No se encontraron roles");
        }

        UserEntity userEntity = UserEntity.builder() //Crear la entidad de usuario
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles(rolesEntitySet)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialNoExpired(true)
                .isEnable(true)
                .build();

        UserEntity userCreated = userRepository.save(userEntity); //Guardar el usuario en la base de datos

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>(); //Crear la lista de autoridades

        //Agregar roles al usuario
        userCreated.getRoles().forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        //Agregar permisos al usuario
        userCreated.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        //Crear la autenticacion con los detalles del usuario creado
        Authentication authentication = new UsernamePasswordAuthenticationToken(userCreated.getUsername(), userCreated.getPassword(), authorityList);

        String authToken = jwtUtils.createToken(authentication); //Generar el token JWT

        AuthResponse authResponse = new AuthResponse(userCreated.getUsername(),"Usuario creado exitosamente", authToken,true); //Crear la respuesta de autenticacion

        return authResponse;
    }
}
