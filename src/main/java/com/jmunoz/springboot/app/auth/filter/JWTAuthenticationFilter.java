package com.jmunoz.springboot.app.auth.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Por defecto, este filtro solo se va a ejecutar cuando nuestra ruta sea login del tipo POST.
// Pero lo hemos cambiado para que nuestra ruta sea /api/login

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

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
}
