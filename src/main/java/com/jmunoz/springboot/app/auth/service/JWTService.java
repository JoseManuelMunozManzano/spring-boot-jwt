package com.jmunoz.springboot.app.auth.service;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

// Se crea esta interfase para desacoplar el código que tiene que ver con JWT y que sea reutilizable
public interface JWTService {

    String create(Authentication auth);

    boolean validate(String token);

    Claims getClaims(String token);

    String getUsername(String token);

    Collection<? extends GrantedAuthority> getRoles(String token);

    String resolve(String token);
}
