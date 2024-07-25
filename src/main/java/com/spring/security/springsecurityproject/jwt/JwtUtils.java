package com.spring.security.springsecurityproject.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

//This component will handles all the util method CRUD of tokens
@Component
public class JwtUtils {
    // LOGGER
    private static final Logger logger =  LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpiryTimeInMs")
    private String jwtExpiryTimeInMs;

    // METHOD TO GET THE TOKEN FROM REQUEST
    public String getJwtTokenFromHeader(HttpServletRequest request){
        // GET THE HEADER FROM THE REQUEST
        String BearerToken = request.getHeader("Authorization");
        logger.debug("Authorization token from the request "+ BearerToken);
        if(BearerToken != null && BearerToken.startsWith("Bearer ")){
            return BearerToken.substring(7);
        }

        return null;
    }

    // GENERATE BEARER TOKEN
    public String generateTokenFromUser(UserDetails userDetails){
        logger.debug("Token created for user "+ userDetails.getUsername());
        return Jwts.builder().subject(userDetails.getUsername())
                .issuedAt(new Date()).expiration(new Date((new Date()).getTime() + jwtExpiryTimeInMs)).signWith(Key()).compact();
    }


    // GET USER NAME FROM TOKEN
    public String getUserNameFromToken(String token){
        return Jwts.parser().verifyWith((SecretKey) Key()).build().parseSignedClaims(token).getPayload().getSubject();
    }

    private Key Key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) Key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
