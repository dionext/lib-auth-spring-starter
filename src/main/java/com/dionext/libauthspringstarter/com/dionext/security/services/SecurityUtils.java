package com.dionext.libauthspringstarter.com.dionext.security.services;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {
    public static boolean isLoggedIn() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //Object principal = authentication.getPrincipal();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            return authentication != null && authentication.isAuthenticated();
        }
        else return false;
    }
    public static String  getUserName() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            String currentUserName = authentication.getName();
            return currentUserName;
        }else{
            throw new RuntimeException("No User");
        }
    }
    public static boolean isUserInAdminRole() {
        return isUserInRole("ADMIN");
    }
    public static boolean isUserInRole(String role) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getAuthorities().stream().anyMatch(
                a -> a.getAuthority().equals("ADMIN"))) {//!!! "ADMIN" not 'ROLE_ADMIN'
            return true;
        }
        return false;
    }
}

