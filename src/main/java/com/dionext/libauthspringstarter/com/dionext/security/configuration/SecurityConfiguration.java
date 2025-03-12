package com.dionext.libauthspringstarter.com.dionext.security.configuration;

import com.dionext.libauthspringstarter.com.dionext.security.entity.User;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authz) -> authz
                        //configure Spring Security Java configuration to allow dispatcher types like FORWARD and ERROR
                        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                        .requestMatchers("/admin/**").hasAuthority(User.ROLE_ADMIN)
                        .requestMatchers("/admin/api/**").hasAuthority(User.ROLE_ADMIN)
                        .requestMatchers("/api/**").authenticated()
                        .requestMatchers("/public/api/**").permitAll()
                        .anyRequest().permitAll()
                )
                .httpBasic(withDefaults())
                //.formLogin(withDefaults())
                .formLogin(form -> form
                        .loginPage("/login") // Custom login page
                        .defaultSuccessUrl("/start") // Redirect after successful login
                        .failureUrl("/login?error=true") // Redirect after failed login
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/start")
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // Logout URL
                        .logoutSuccessUrl("/login?logout=true") // Redirect after logout
                        .permitAll()
                )
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

}
