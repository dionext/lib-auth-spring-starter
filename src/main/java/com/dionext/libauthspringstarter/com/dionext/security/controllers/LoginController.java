package com.dionext.libauthspringstarter.com.dionext.security.controllers;

import com.dionext.libauthspringstarter.com.dionext.security.services.UserDetailsServiceImpl;
import com.dionext.site.services.PageCreatorService;
import com.dionext.utils.services.I18nService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@Slf4j
public class LoginController {
    @Autowired
    PageCreatorService pageCreatorService;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private I18nService i18n;

    @GetMapping("/login")
    public String login(Model model) {
        pageCreatorService.prepareTemplateModel(model);
        return "login"; // Return the login.html template
    }
    @GetMapping("/start")
    public String start(Model model) {
        pageCreatorService.prepareTemplateModel(model);
        return "start";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        pageCreatorService.prepareTemplateModel(model);
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username,
                               @RequestParam String password,
                               @RequestParam String email,
                               Model model,
                               RedirectAttributes redirectAttributes) {
        pageCreatorService.prepareTemplateModel(model);
        try {
            userDetailsService.registerUser(username, password, email);
            String message = i18n.getString("register.confirm.letter.message");
            log.info("message: " + message);
            redirectAttributes.addFlashAttribute("message", 
                message);
            return "redirect:/login"; // Перенаправление на страницу входа
        } catch (Exception e) {
            log.error("Error register user", e);
            model.addAttribute("error", e.getMessage());
            pageCreatorService.prepareTemplateModel(model);
            return "register";
        }
    }

    @GetMapping("/confirm-email")
    public String confirmEmail(@RequestParam String token, RedirectAttributes redirectAttributes) {
        try {
            userDetailsService.confirmEmail(token);
            redirectAttributes.addFlashAttribute("message", 
                i18n.getString("register.confirm.letter.success"));
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", 
                i18n.getString("register.confirm.letter.error"));
        }
        return "redirect:/login";
    }
}