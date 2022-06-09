package com.jmunoz.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
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
import java.security.Key;
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

        // Dejar claro que este no es el JSON Web Token
        // Este token se maneja de forma interna en nuestra aplicación con Spring Security y a partir de el
        // objeto Authentication se puede obtener el username y todos los datos necesarios para crear el
        // JSON Web Token
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

    // Aquí vemos el objeto Authentication authResult que es el mismo que tenemos arriba, con la diferencia
    // de que aquí ya está autenticado (atributo authenticated en true) y con los datos del usuario, username,
    // sus roles.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        // Empezamos a crear el JSON Web Token que tenemos que retornar al cliente. Por ahora sencillo.
        // Falta agregar roles y la fecha de expiración
        //
        // Hay varias formas de obtener el nombre del usuario:
        // authResult.getName()
        // ((User) authResult.getPrincipal()).getUsername()
        String username = ((User) authResult.getPrincipal()).getUsername();

        String token = Jwts.builder()
                .setSubject(username)
                .signWith(SECRET_KEY)
                .compact();

        // Pasamos el token en la cabecera de la respuesta.
        // Es obligatorio que el nombre del parámetro sea Authorization
        // El valor del token, como standard, se inicia con el prefijo Bearer, seguido de espacio y el token
        // Cuando el cliente envíe el token, también tendrá que poner el prefijo "Bearer "
        response.addHeader("Authorization", "Bearer " + token);

        // Pero también es recomendable pasar el token y cualquier otro atributo que queramos pasar al usuario en
        // una estructura JSON
        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", username));

        // Para pasar estos datos a la respuesta obtenemos el writer de la respuesta y escribir, pero
        // transformando un objeto Map a uno JSON
        // Para eso se usa ObjectMapper, que permite transformar cualquier objeto Java en un JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));

        // Indicamos el status de la petición como OK
        response.setStatus(200);

        // Indicamos el content-type, indicando que retornamos un JSON
        response.setContentType("application/json");
    }
}
