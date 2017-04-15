package com.speed.mixer.web.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by sambit on 4/10/2017.
 */
@RestController
public class AccountController {

    @GetMapping("/public/account/{accountNumber}")
    public String getPublicAccountDetail(@PathVariable final int accountNumber){
        return "Public account linked to :: "+accountNumber;
    }
    @GetMapping("/private/account/{accountNumber}")
    public String getPrivateAccountDetail(@PathVariable final int accountNumber){
        return "Private account linked to :: "+accountNumber;
    }
    @GetMapping("/private/admin/account/{accountNumber}")
    public String getPrivateAdminAccountDetail(@PathVariable final int accountNumber){
        return "Private extra account linked to :: "+accountNumber;
    }
}
