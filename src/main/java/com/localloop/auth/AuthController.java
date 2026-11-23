package com.localloop.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.localloop.auth.EmailActionToken.Purpose;

import static com.localloop.auth.AuthRateLimit.Scope.MAIL_EMAIL;
import static com.localloop.auth.AuthRateLimit.Scope.MAIL_IP;
import static com.localloop.auth.AuthRateLimit.Scope.REDEEM_IP;

@Controller
class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String MAIL_ACK = "If the address is eligible, you’ll receive an email with next steps.";

    private final AuthService auth;
    private final AuthInput input;
    private final AuthRateLimit rate;

    AuthController(AuthService auth, AuthInput input, AuthRateLimit rate) {
        this.auth = auth;
        this.input = input;
        this.rate = rate;
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/register")
    String register() {
        return "register";
    }

    @PostMapping("/register")
    String register(@RequestParam(required = false) String email, HttpServletRequest request, RedirectAttributes flash) {
        return requestLink(email, Purpose.ACTIVATE, request, flash, "/register");
    }

    @GetMapping("/forgot-password")
    String forgotPassword() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    String forgotPassword(@RequestParam(required = false) String email, HttpServletRequest request,
                          RedirectAttributes flash) {
        return requestLink(email, Purpose.RESET, request, flash, "/forgot-password");
    }

    private String requestLink(String email, Purpose purpose, HttpServletRequest request, RedirectAttributes flash,
                               String redirectPath) {
        if (rate.allow(MAIL_IP, request.getRemoteAddr())) {
            String normalized = input.email(email);
            if (!normalized.isEmpty() && rate.allow(MAIL_EMAIL, normalized)) {
                auth.requestLink(normalized, purpose);
            }
        }
        flash.addFlashAttribute("message", MAIL_ACK);
        return "redirect:" + redirectPath;
    }

    @GetMapping("/activate")
    String activate(@RequestParam(required = false) String token, Model model) {
        return tokenForm(token, Purpose.ACTIVATE, model);
    }

    @PostMapping("/activate")
    String activate(@RequestParam(required = false) String token, @RequestParam(required = false) String name,
                    @RequestParam(required = false) String password, HttpServletRequest request, Model model,
                    RedirectAttributes flash) {
        return redeem(token, name, password, Purpose.ACTIVATE, request, model, flash);
    }

    @GetMapping("/reset-password")
    String resetPassword(@RequestParam(required = false) String token, Model model) {
        return tokenForm(token, Purpose.RESET, model);
    }

    @PostMapping("/reset-password")
    String resetPassword(@RequestParam(required = false) String token, @RequestParam(required = false) String password,
                         HttpServletRequest request, Model model, RedirectAttributes flash) {
        return redeem(token, null, password, Purpose.RESET, request, model, flash);
    }

    private String tokenForm(String token, Purpose purpose, Model model) {
        if (auth.usable(token, purpose)) {
            model.addAttribute("token", token);
        } else {
            model.addAttribute("error", "This link is invalid or expired. Request a new link to continue.");
        }
        return purpose.path.substring(1);
    }

    private String redeem(String token, String name, String password, Purpose purpose, HttpServletRequest request,
                          Model model, RedirectAttributes flash) {
        String view = purpose.path.substring(1);
        if (!rate.allow(REDEEM_IP, request.getRemoteAddr())) {
            model.addAttribute("error", "Too many attempts. Wait a minute before trying again.");
            return view;
        }
        name = name == null ? null : name.strip();
        boolean validPassword = AuthInput.newPassword(password);
        if (!validPassword || purpose == Purpose.ACTIVATE && !AuthInput.displayName(name)) {
            tokenForm(token, purpose, model);
            if (model.containsAttribute("token")) {
                model.addAttribute("error", !validPassword
                        ? "Use a password between 12 and 72 UTF-8 bytes."
                        : "Enter a display name with 1 to 100 characters and no control characters.");
            }
            return view;
        }
        if (!auth.redeem(token, purpose, name, password)) {
            model.addAttribute("error", "This link is invalid or expired. Request a new link to continue.");
            return view;
        }
        log.info("Authentication link redeemed ({})", purpose);
        flash.addFlashAttribute("message", purpose == Purpose.ACTIVATE
                ? "Your account is active. You can now sign in." : "Your password was reset. Sign in with your new password.");
        return "redirect:/login";
    }

    @GetMapping("/dashboard")
    String dashboard(@AuthenticationPrincipal AuthenticatedUser user, Model model) {
        model.addAttribute("displayName", user.displayName());
        model.addAttribute("email", user.getUsername());
        model.addAttribute("role", user.role());
        return "dashboard";
    }
}
