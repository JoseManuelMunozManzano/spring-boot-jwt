package com.jmunoz.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// Por defecto, este filtro solo se va a ejecutar cuando nuestra ruta sea login del tipo POST.
// Pero lo hemos cambiado para que nuestra ruta sea /api/login

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = this.obtainUsername(request);
        username = username != null ? username : "";
        username = username.trim();
        String password = this.obtainPassword(request);
        password = password != null ? password : "";

        if (username != null && password != null) {
            logger.info("Username desde request parameter (form-data): " + username);
            logger.info("Password desde request parameter (form-data): " + password);
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        // Se devuelve la autenticación
        // Esta es una forma cuando se envía el usuario y el password como parámetros del request, por ejemplo
        // usando Postman.
        // Para probar esto en Postman:
        // POST
        // http://localhost:8080/api/login
        // En Body,
        // Forma1: Seleccionar form-data
        //   Las claves-valores que ahí se informan se envían en el request y se recuperan usando request.getParameter()
        //   Las claves se tienen que llamar username y password
        //     username     jmunoz
        //     password     1234
        // Forma 2: Seleccionar raw y JSON   (Todavía no está hecho)
        //   Mandar un JSON con el usuario y la contraseña
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        // Empezamos a crear el JSON Web Token que tenemos que retornar al cliente.
        String username = ((User) authResult.getPrincipal()).getUsername();

        // Obteniendo los roles
        // El tipo se ha obtenido haciendo Cmd+Click en getAuthorities()
        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

        // Se va a colocar más información en el token, en concreto la fecha de creación, de expiración y los roles.
        //
        // Como no hay un setRoles() ni nada parecido, los roles se añaden como datos extra, llamados Claims.
        // Lo ideal es que roles se guarden como String. En este caso se está guardando como Object, pero está bien
        // porque automáticamente se transformará en String.
        // Pero lo importante es que tenga un formato JSON, es decir, String con estructura JSON.
        // Si que existe un setClaims para añadir los claims.
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(SECRET_KEY)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 14400000L))
                .compact();

        response.addHeader("Authorization", "Bearer " + token);

        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", username));

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));

        response.setStatus(200);

        response.setContentType("application/json");
    }
}
