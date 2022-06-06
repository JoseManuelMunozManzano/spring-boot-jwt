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
        http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale", "/api/clientes/**").permitAll()
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
