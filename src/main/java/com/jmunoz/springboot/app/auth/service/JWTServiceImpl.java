package com.jmunoz.springboot.app.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmunoz.springboot.app.auth.SimpleGrantedAuthorityMixin;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

// Se marca como @Component para poder inyectarlo.
// Pero no se puede inyectar en el filtro porque no se pueden inyectar objetos.
// Se va a inyectar en la clase de configuración de Spring (SpringSecurityConfig) pasándolo por el constructor.
@Component
public class JWTServiceImpl implements JWTService {

    public static final SecretKey SECRET_KEY = new SecretKeySpec("algunaLlaveSecretaTienequeser256bitslong".getBytes(), SignatureAlgorithm.HS512.getJcaName());
    // Otra forma en base64
    // public static final String SECRET = Base64Utils.encodeToString("algunaLlaveSecretaTienequeser256bitslong".getBytes());

    public static final long EXPIRATION_DATE = 14400000L;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

    @Override
    public String create(Authentication auth) throws IOException {
        String username = ((User) auth.getPrincipal()).getUsername();

        Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(SECRET_KEY)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
                .compact();

        return token;
    }

    @Override
    public boolean validate(String token) {
        try {
            getClaims(token);
            return true;
        }  catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().
                parseClaimsJws(resolve(token)).getBody();
    }

    @Override
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    @Override
    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
        Object roles = getClaims(token).get("authorities");

        Collection<? extends GrantedAuthority> authorities = Arrays.asList(
                new ObjectMapper().addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class).
                        readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));

        return authorities;
    }

    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith(TOKEN_PREFIX)) {
            return token.replace(TOKEN_PREFIX, "");
        }

        return null;
    }
}
