package com.dionext.libauthspringstarter.com.dionext.security.services;

import com.dionext.libauthspringstarter.com.dionext.security.entity.User;
import com.dionext.libauthspringstarter.com.dionext.security.repositories.UserRepository;
import com.dionext.libauthspringstarter.com.dionext.security.entity.ConfirmationToken;
import com.dionext.libauthspringstarter.com.dionext.security.repositories.ConfirmationTokenRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${d.user.password:unknown}")
    String userPassword;
    @Value("${d.admin.password:unknown}")
    String adminPassword;


    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    
    @Autowired
    private EmailService emailService;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostConstruct
    void postConstruct() {
        //List<User> users = userRepository.findAll();

        User user = userRepository.findByUsername("user").orElse(null);
        if (user == null) {
            user = new User();
            user.setUsername("user");
            user.setPassword(new BCryptPasswordEncoder().encode(userPassword));
            //user.setPassword("{noop}user");
            user.setRoles(User.ROLE_USER);
            user.setEnabled(true);
            userRepository.save(user);
        }

        user = userRepository.findByUsername("admin").orElse(null);
        if (user == null) {
            user = new User();
            user.setUsername("admin");
            user.setPassword(bCryptPasswordEncoder.encode(adminPassword));
            user.setRoles(User.ROLE_ADMIN);
            user.setEnabled(true);
            userRepository.save(user);
        }

    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> personOptional = userRepository.findByUsername(username);
        if (personOptional.isEmpty()) {
            throw new UsernameNotFoundException("Username %s does not exist".formatted(username));
        }
        if (!personOptional.get().isEnabled()) {
            throw new UsernameNotFoundException("Please confirm your email first");
        }
        User person = personOptional.get();
        return new org.springframework.security.core.userdetails.User(person.getUsername(),
                person.getPassword(), getAuthorities(person));
    }

    //private Collection<? extends GrantedAuthority> getAuthorities(UserDto person) {
    //todo
    //  return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + person.getRoles()));
    //}

    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        return User.getRolesList(user).stream().map(s -> new SimpleGrantedAuthority(s)).collect(Collectors.toList());
        // Split the authorities string and convert to a list of SimpleGrantedAuthority objects
        //return Arrays.stream(roles.split(","))
          //      .map(SimpleGrantedAuthority::new)
            //    .collect(Collectors.toList());
    }


    @Transactional
    public void registerUser(String username, String password, String email) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalStateException("Username already taken");
        }
        
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalStateException("Email already registered");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setRoles(User.ROLE_USER);
        user.setEmail(email);
        user.setEnabled(false); // User starts as disabled until email is confirmed
        
        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(
            token,
            LocalDateTime.now(),
            LocalDateTime.now().plusHours(24),
            user.getId()
        );
        
        confirmationTokenRepository.save(confirmationToken);

        try {
            emailService.sendConfirmationEmail(email, token);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to send confirmation email", e);
        }
    }

    @Transactional
    public void confirmEmail(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository
            .findByToken(token)
            .orElseThrow(() -> new IllegalStateException("Token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();
        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Token expired");
        }

        confirmationToken.setConfirmedAt(LocalDateTime.now());
        confirmationTokenRepository.save(confirmationToken);

        User user = userRepository.findById(confirmationToken.getUserId()).orElse(null);
        if (user != null) {
            user.setEnabled(true);
            userRepository.save(user);
        }
    }
}

