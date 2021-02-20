package com.kuplumosk.security.controllers;

import com.kuplumosk.security.entitys.User;
import com.kuplumosk.security.services.UserService;
import java.security.Principal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MainController {

    private final UserService userService;

    @Autowired
    public MainController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/user")
    public String userPage(Model model, Principal principal) {
        User user = userService.findByUsername(principal.getName());
        model.addAttribute("username", user.getUsername());
        model.addAttribute("email", user.getEmail());
        return "user";
    }

    @GetMapping("/admin")
    public String showUserList(Model model) {
        model.addAttribute("users", userService.findAllUsers());
        return "admin";
    }

    @GetMapping("admin/new")
    public String addUserPage(@ModelAttribute("user") User user, Model model) {
        model.addAttribute("roles", userService.findAllRoles());
        return "add-user";
    }

    @PostMapping("/adduser")
    public String addUser(@ModelAttribute("user") User user, @RequestParam("role_select") Long[] roleIds) {
        for (Long id : roleIds) {
            user.addRole(userService.getRoleById(id));
        }
        userService.addUser(user);
        return "redirect:/admin";
    }

    @PostMapping("admin/update/{id}")
    public String updateUser(@ModelAttribute("user") User user, @RequestParam("role_select") Long[] roleIds) {
        for (Long id : roleIds) {
            user.addRole(userService.getRoleById(id));
        }
        userService.updateUser(user);
        return "redirect:/admin";
    }

    @GetMapping("admin/edit/{id}")
    public String showUpdateForm(@PathVariable("id") long id, Model model) {
        userService.findById(id);
        model.addAttribute("roles", userService.findAllRoles());
        model.addAttribute("user", userService.findById(id));
        return "/update-user";
    }

    @GetMapping("admin/delete/{id}")
    public String deleteUser(@PathVariable("id") long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }
}
