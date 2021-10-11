package com.example.springbootkeycloak;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@RestController
public class HelloController {


    @GetMapping("/hello")
    public ResponseEntity<String> hello(Authentication authentication){

        if (authentication.getPrincipal() instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> kp = (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
            AccessToken token = kp.getKeycloakSecurityContext().getToken();
            final String body = "Hi,  " + token.getName();
            return ResponseEntity.ok(body);
        }
        return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
    }

    @GetMapping(path = "/logout")
    public void logout(HttpServletRequest request, HttpServletResponse httpServletResponse) throws ServletException {
        request.logout();
        httpServletResponse.setHeader("Location", "/hello");
        httpServletResponse.setStatus(302);
    }
}
