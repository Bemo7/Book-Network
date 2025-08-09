package com.bemojr.book_network.filter;

import com.bemojr.book_network.repository.UserRepository;
import com.bemojr.book_network.service.JwtService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private static final String AUTH_ROUTE_PATTERN = "^/auth/[a-zA-z0-9-/]*";
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("Servlet path -> {}", request.getServletPath());
        if (request.getServletPath().matches(AUTH_ROUTE_PATTERN)) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);

        final SecurityContext securityContext = SecurityContextHolder.getContext();

        if (
                userEmail != null &&
                        securityContext.getAuthentication() != null &&
                        !securityContext.getAuthentication().isAuthenticated()
        ) {
            UserDetails userDetails = userRepository.findByEmail(userEmail).orElseThrow(() -> new EntityNotFoundException("User Not Found!"));

            if (jwtService.isTokenValid(jwt, userDetails)) {
                updateSecurityContext(request, userDetails, securityContext);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void updateSecurityContext(HttpServletRequest request,UserDetails userDetails, SecurityContext securityContext) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        authenticationToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        securityContext.setAuthentication(authenticationToken);
    }
}
