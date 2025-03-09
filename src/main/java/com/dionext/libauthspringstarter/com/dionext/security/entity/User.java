package com.dionext.libauthspringstarter.com.dionext.security.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
@Setter
@Entity
public class User {

    final public static String ROLE_USER = "USER";
    final public static String ROLE_ADMIN = "ADMIN";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    @JsonIgnore
    private String password;

    @Column(nullable = false)
    private String roles;

    @Column(name = "oauth2_provider")
    private String provider;

    @Column(name = "oauth2_id")
    private String providerId;

    public User() {
    }

    public User(String username, String password, String roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public User(String username, String email, String provider, String providerId) {
        this.username = username;
        this.email = email;
        this.provider = provider;
        this.providerId = providerId;
        this.roles = ROLE_USER;
        this.password = "{noop}"; // No password for OAuth2 users
    }

    public Long getId() {
        return id;
    }
    @Column(unique = true)
    private String email;

    @Column
    @ColumnDefault("false")
    private boolean enabled;

    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean b) {
        this.enabled = b;
    }
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getRoles() {
        return roles;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }

    static public Collection<String> getRolesList(User user){
        if (user.getRoles() == null) return new ArrayList<String>();
        else return Stream.of(user.getRoles().split(",", -1))
                .collect(Collectors.toList());
    }
    static public void setRolesList(User user, Collection<String> roles){
        if (roles.size() > 0) user.setRoles(String.join(",", roles));
        else user.setRoles(null);
    }


}
