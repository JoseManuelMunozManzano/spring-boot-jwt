package com.jmunoz.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

// SEGUNDA PARTE: SE EJECUTA CUANDO QUEREMOS ACCEDER A UN RECURSO
// Una vez que estamos autenticados, ya se puede enviar el token para acceder a los recursos protegidos.
// Hay que crear ahora un segundo filtro que sería JWTAuthorizationFilter, que se ejecuta en cada request,
// cuyos pasos son:
// 1. Verificar la firma del JWT. Tiene que venir en el header la key Authorization con Bearer y el token
// 2. Si el token es válido:
//      2.1. Se obtienen, del token, los datos del usuario (claims)
//      2.2. Se autentica y se verifican los permisos
//      2.3. Si tiene permisos:
//          2.3.1. Puede acceder al recurso
//      2.4. Si NO tiene permisos:
//          2.4.1. Se envía un 403 Forbidden, acceso denegado
// 3. Si el token NO es válido:
//      3.1. Se envía un 403 Forbidden, acceso denegado
// 4. Si no viene token, nos saltamos el filtro
//
// Para probar en Postman, el recurso va a ser un GET a: http://localhost:8080/api/clientes/listar
// Y en la pestaña Authorization en Type poner: Bearer Token
// Y pegar el token que nos dio en el POST a la ruta: http://localhost:8080/api/login
// Esto añade automáticamente la key Authorization en el header
// con Body raw y JSON:
// {
//    "username": "jmunoz",
//    "password": 1234
// }

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public static final SecretKey SECRET_KEY = new SecretKeySpec("algunaLlaveSecretaTienequeser256bitslong".getBytes(), SignatureAlgorithm.HS512.getJcaName());

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String header = request.getHeader("Authorization");

        if (!requiresAuthentication(header)) {
            chain.doFilter(request, response);
            return;
        }

        // Clave Secreta, quitamos el Bearer del token y obtenemos los datos del mismo.
        boolean validoToken;
        Claims token = null;
        try {
            token = Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().
                    parseClaimsJws(header.replace("Bearer ", "")).getBody();

            validoToken = true;
        }  catch (JwtException | IllegalArgumentException e) {
            validoToken = false;
        }

        // Cada vez que queramos acceder a un recurso nos autenticamos con el token de cuando hicmos el login
        UsernamePasswordAuthenticationToken authentication = null;
        if (validoToken) {
            String username = token.getSubject();
            // En la clase JWTAuthenticationFilter guardamos, en el método successfulAuthentication,
            // en los claims con la key "authorities"
            Object roles = token.get("authorities");

            // Los roles son un JSON que hay que convertir en una colección de authorities
            // ERROR COMUN:
            // Cannot construct instance of `org.springframework.security.core.authority.SimpleGrantedAuthority`
            // (although at least one Creator exists): cannot deserialize from Object
            // value (no delegate- or property-based Creator)
            // Esto ocurre porque SimpleGrantedAuthority recibe un parámetro (el role)
            // No hay constructor vacío.
            //
            // SOLUCION
            // 1. Una de las cosas que nos permite ObjectMapper es crear otra clase y combinarla (clase Mixin),
            // en este caso, con SimpleGrantedAuthority.
            //
            // 2. Otra forma sería crear nuestra propia implementación de GrantedAuthority y utilizarla en vez de
            // SimpleGrantedAuthority
            Collection<? extends GrantedAuthority> authorities = Arrays.asList(
                    new ObjectMapper().readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));

            authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        }

        // Manejando el contexto de seguridad. Asignamos el objeto authentication dentro del contexto.
        // Es para autenticar al usuario dentro del request.
        // No estamos utilizando sesiones, así que la autenticación es por solicitud.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Continuamos con los siguientes filtros (Sería como el next() en NodeJs)
        chain.doFilter(request, response);
    }

    protected boolean requiresAuthentication(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return false;
        }

        return true;
    }
}
