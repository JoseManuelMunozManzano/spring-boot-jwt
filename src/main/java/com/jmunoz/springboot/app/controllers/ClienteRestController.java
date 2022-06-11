package com.jmunoz.springboot.app.controllers;

import com.jmunoz.springboot.app.models.service.IClienteService;
import com.jmunoz.springboot.app.view.xml.ClienteList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    // Descomentar si se quiere probar que solo rol de administrador pueden acceder a esta ruta
    @GetMapping(value = "/listar")
//    @Secured("ROLE_ADMIN")
    public ClienteList listar() {

        return new ClienteList(clienteService.findAll());
    }
}
