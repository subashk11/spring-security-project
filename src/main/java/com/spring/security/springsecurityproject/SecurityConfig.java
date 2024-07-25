package com.spring.security.springsecurityproject;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // Datasource for Creating query from the schema.
    @Autowired
    private DataSource dataSource;

    //CREATE CUSTOM FILTER CHAIN - REFER SpringbootWebSecurityConfiguration class to implement filter chain
    //BEAN - TO ADD CUSTOM FILTER CHAIN IS DECLARED IN A BEAN
    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        // CONFIG REQUESTS THAT NEEDS TO BE AUTHENTICATED
        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());
        // CONFIG TO MAINTAIN STATE : SessionId if its a Statefull API , Stateless doesn't have any session id and spring context
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // USED TO AUTHENTICATE FORM BASED LOGIN
        // http.formLogin(withDefaults());
        // USED TO TEST WHERE THERE IS NO FORM - DIFFERENT FRONT END / POSTMAN
        http.httpBasic(withDefaults());
        // DISABLE CSRF
        http.csrf( csrf -> csrf.disable());
        // ENABLE FRAMES TO DISPLAY H2 DATABASE
        http.headers(header -> header.frameOptions( frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
        // BUILD WILL BUNDLE THE CONFIG AND ADD FILTER TO THE LIST OF FILTER CHAINS
        return http.build();
    }


    //CREATE IN MEMORY USERS AND THEIR ROLES TO ALL ACCESS/ AUTHORIZATION
    @Bean
    public UserDetailsService getUserDetailsService(){
        // USERS SHOULD BE OF USER DETAILS
        UserDetails user1 = User.withUsername("user1").password("{noop}user@123").roles("USER").build();
        UserDetails admin1 = User.withUsername("admin1").password("{noop}admin@123").roles("ADMIN").build();

        // TO TEST - USERS CREATED IN MEMORY THIS CLASS IS USED.
//        return new InMemoryUserDetailsManager(user1, admin1);

        // TO CREATE USER IN H2
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin1);

        return userDetailsManager;
    }
}
