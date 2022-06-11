package com.jmunoz.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

// Se desarrolla la solución 1, consistente en crear una clase Mixin abstracta
// que implementa un constructor vacío
public abstract class SimpleGrantedAuthoritiesMixin {

    // Con esta anotación indicamos que este es el constructor por defecto cuando se crean objetos authorities
    // a partir de JSON
    // Se indica que atributo del JSON se va a inyectar en el constructor y que corresponde al String role.
    // El property es "authority" porque cuando se hace el login, en el token van los roles asociados a la propiedad
    // authority
    @JsonCreator
    public SimpleGrantedAuthoritiesMixin(@JsonProperty("authority") String role) {}
}
