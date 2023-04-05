package com.lyc.controller;

import com.lyc.domain.ResponseResult;
import com.lyc.domain.User;
import com.lyc.service.UserLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @Autowired
    private UserLoginService userLoginService;

    @PostMapping("/user/login")
    public ResponseResult loginUser(@RequestBody User user){
        return  userLoginService.login(user);
    }
    @RequestMapping("/user/logout")
    public ResponseResult logoutUser(){
        return userLoginService.logOut();
    }
}
