package com.jmunoz.springboot.app;

import com.jmunoz.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.jmunoz.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.jmunoz.springboot.app.auth.handler.CustomAuthenticationEntryPoint;
import com.jmunoz.springboot.app.auth.handler.LoginSuccessHandler;
import com.jmunoz.springboot.app.auth.service.JWTService;
import com.jmunoz.springboot.app.models.service.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

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

    // Aquí es donde inyectamos nuestra componente JWTService
    @Autowired
    private JWTService jwtService;

    @Autowired
    public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
        builder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Quitamos el acceso a /api/clientes porque le vamos a dar seguridad.
        //
        // Quitamos el formulario Login y el Logout y el accessDeniedPage, ya que se va a manejar de forma
        // automática con los códigos http.
        // Si ahora en Postman ejecutamos: http://localhost:8080/api/clientes/listar
        // Nos da el error 403, que es lo que queremos
        // NOTA: Por ahora no aparece ningún json, solo se indica el error
        http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar/**", "/locale").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                // Registramos el filtro de autenticación y tenemos que pasarle el AuthenticationManager y nuestro
                // JWTService.
                // Como SpringSecurityConfig está heredando de WebSecurityConfigurerAdapter, si revisamos la clase
                // abstracta, vemos que existe un método que nos permite obtener el AuthenticationManager y que se
                // llama authenticationManager()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
                // Registramos el filtro de autorización
                .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }
}
