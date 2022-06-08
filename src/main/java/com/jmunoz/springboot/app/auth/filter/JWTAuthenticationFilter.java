package com.jmunoz.springboot.app.auth.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Vamos a hacer un filtro adaptado para trabajar con JWT, que se encarga de realizar la autenticación.
// El cliente envía las credenciales (username y password) bajo cierto url login y bajo cierto tipo de petición,
// por ejemplo un POST.
// Este filtro interceptor que se ejecuta en el request, antes de llamar al controlador y al método handler,
// realiza el login, según las credenciales.
//
// Hereda de la clase UsernamePasswordAuthenticationFilter y tenemos que customizarla a lo que queremos que haga JWT
// Si vamos a UsernamePasswordAuthenticationFilter veremos que en el constructor aparece la ruta /login y el método
// POST
// Por defecto, este filtro solo se va a ejecutar cuando nuestra ruta sea login del tipo POST.

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // Este es el encargado de realizar el login según nuestro proveedor JpaUserDetailsService
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // Método que se encarga de intentar realizar la autenticación.
    // Por debajo este método trabajar con nuestro proveedor de autenticación.
    //
    // Por ejemplo, nuestro proveedor de autenticación JPA es, en el package models/service,
    // la clase JpaUserDetailsService, método loadUserByUsername, que realiza el login al estilo JPA.
    //
    // Por tanto, este método va a llamar a un componente llamado AuthenticationManager que se encarga de trabajar
    // de la mano con el proveedor JpaUserDetailsService.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // Este código lo hemos cogido de UsernamePasswordAuthenticationFilter
        // Por debajo, this.obtainUsername(request); obtiene el username usando request.getParameter("username")
        // y this.obtainPassword(request); obtiene el password usando request.getParameter("password")
        String username = this.obtainUsername(request);
        username = username != null ? username : "";
        username = username.trim();
        String password = this.obtainPassword(request);
        password = password != null ? password : "";

        if (username != null && password != null) {
            // Podemos usar el Logger porque aparece en alguna clase abstracta de UsernamePasswordAuthenticationFilter
            logger.info("Username desde request parameter (form-data): " + username);
            logger.info("Password desde request parameter (form-data): " + password);
        }

        // Aquí creamos el UsernamePasswordAuthenticationToken, que se encarga de contener las credenciales.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        // Se devuelve la autenticación
        // Esta es una forma cuando se envía el usuario y el password como parámetros del request, por ejemplo
        // usando Postman.
        // Para probar esto en Postman:
        // POST
        // http://localhost:8080/login
        // En Body,
        // Forma1: Seleccionar form-data
        //   Las claves-valores que ahí se informan se envían en el request y se recuperan usando request.getParameter()
        //   Las claves se tienen que llamar username y password
        //     username     jmunoz
        //     password     1234
        // Forma 2: Seleccionar raw y JSON
        //   Mandar un JSON con el usuario y la contraseña
        return authenticationManager.authenticate(authToken);

        // Para que to-do esto funcione lo tenemos que registrar en alguna parte.
        // Se hace en la configuración, en SpringSecurityConfig
        //
        // Ahora falta que nuestro filtro retorne un Json con nuestro Json Web Token (la autenticación) que
        // guardaremos en el cliente. Una vez lo tengamos guardado en nuestra aplicación, sea el SessionStorage o
        // el LocalStorage, cada vez que se realice una petición al servidor que requiera autenticación,
        // enviaremos nuestro token para poder autenticarlo.
    }
}
