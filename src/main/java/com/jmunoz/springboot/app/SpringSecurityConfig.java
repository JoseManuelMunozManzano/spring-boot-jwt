package com.jmunoz.springboot.app;

import com.jmunoz.springboot.app.auth.handler.LoginSuccessHandler;
import com.jmunoz.springboot.app.models.service.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// Adaptando la configuración de la seguridad para trabajar con jwt
// Dejamos de usar sesiones y utilizaremos la forma stateless (sin estado)
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JpaUserDetailsService userDetailsService;

    @Autowired
    private LoginSuccessHandler successHandler;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
        builder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Quitamos el acceso a /api/clientes porque le vamos a dar seguridad.
        //
        // Para ver sus datos, volver a ponerlo y, en Postman, hacer una petición GET a
        // http://localhost:8080/api/clientes/listar
        //
        // Pero si lo quitamos, si vamos a Postman y ejecutamos ese GET, como ahora tiene seguridad, redirige a Login
        // y veremos el código HTML de la vista Login
        //
        // Pera esa no es la idea, ya que queremos que nos muestre el código 401 Not Authorized o 403 Forbidden.
        // Es por esto que hay incompatibilidad entre seguridad normal con sesiones con formulario Login y
        // seguridad basada en token. No se ajusta bien a una o a otra.
        // Lo idea es tener completamente separado nuestra aplicación para Rest de la parte Web.
        // Pero se puede mezclar, lo que pasa es que no se recomienda.
        http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale").permitAll()
                .anyRequest().authenticated()
                .and()
                    .formLogin()
                        .successHandler(successHandler)
                        .loginPage("/login")
                    .permitAll()
                .and()
                .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403")
                .and()
                // 1. Deshabilitamos la protección csrf porque usaremos jwt y no el token de protección de csrf.
                // csrf es más que nada para cuando se trabaja con formularios de Spring más que con Rest.
                // Tenemos que quitar los input csrf que tengamos en los formularios de forma explícita.
                .csrf().disable()
                // 2. Configurar Spring Security, habilitando la configuración en el Session Manager como stateless
                // por sobre el uso de sesiones.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }
}
