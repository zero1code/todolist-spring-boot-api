package br.com.airtonoliveira.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.airtonoliveira.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var serveltPath = request.getServletPath();
        if (serveltPath.startsWith("/tasks/")) {
            //autenticacao (username, senha)
            var authorization = request.getHeader("Authorization");

            var authEncoded = authorization.substring("Basic".length()).trim();
            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecode);
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            //validar usuario
            var user = userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(HttpStatus.UNAUTHORIZED.value());
            } else {
                //validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("idUser", user.getId());
                    //prosseguir
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(HttpStatus.UNAUTHORIZED.value());
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
