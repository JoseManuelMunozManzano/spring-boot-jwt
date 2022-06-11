package com.jmunoz.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jmunoz.springboot.app.auth.service.JWTService;
import com.jmunoz.springboot.app.auth.service.JWTServiceImpl;
import com.jmunoz.springboot.app.models.entity.Usuario;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// PRIMERA PARTE: SE EJECUTA CUANDO QUEREMOS INICIAR SESION
// Por defecto, este filtro solo se va a ejecutar cuando nuestra ruta sea login del tipo POST.
// Pero lo hemos cambiado para que nuestra ruta sea /api/login

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    // Como hemos dicho en JWTServiceImpl, no se puede inyectar el objeto. Se pasa por el constructor
    private JWTService jwtService;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
        this.jwtService = jwtService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = this.obtainUsername(request);
        String password = this.obtainPassword(request);

        if (username != null && password != null) {
            logger.info("Username desde request parameter (form-data): " + username);
            logger.info("Password desde request parameter (form-data): " + password);
        } else {
            Usuario user = null;
            try {
                user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);

                username = user.getUsername();
                password = user.getPassword();

                logger.info("Username desde request InputStream (raw): " + username);
                logger.info("Password desde request InputStream (raw): " + password);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        // Usando nuestro service
        String token = jwtService.create(authResult);

        response.addHeader(JWTServiceImpl.TOKEN_PREFIX, JWTServiceImpl.TOKEN_PREFIX + token);

        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", ((User) authResult.getPrincipal()).getUsername()));

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    // Método que se encarga de implementar la falla del método login
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {

        Map<String, Object> body = new HashMap<>();
        // Es importante por temas de seguridad NO especificar cuál de los dos, username o password, es el incorrecto
        body.put("mensaje", "Error de autenticación: username o password incorrecto!");
        // El mensaje original que ha ocurrido
        body.put("error", failed.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401);
        response.setContentType("application/json");
    }
}
