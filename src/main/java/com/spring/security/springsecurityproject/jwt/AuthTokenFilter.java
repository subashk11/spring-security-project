package com.spring.security.springsecurityproject.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private final static Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    // AUTOWIRED UTIL TO HANDLE JWT TOKEN
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // GET THE JWT TOKEN FROM THE REQUEST
        logger.debug("Filter for json web token is trigger for the reqeust");
        try{
            String token = parse(request);

            if(token != null && jwtUtils.validateJwtToken(token)){
                String userName = jwtUtils.getUserNameFromToken(token);

                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                UsernamePasswordAuthenticationToken authentication = new  UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch ( Exception e){
            logger.error("Error while applying the filer : ", e);
        }

        filterChain.doFilter(request, response);
    }

    public String parse(HttpServletRequest httpServletRequest){
        String JwtToken = jwtUtils.getJwtTokenFromHeader(httpServletRequest);
        logger.debug("Token extracted from the header");
        return JwtToken;
    }
}
