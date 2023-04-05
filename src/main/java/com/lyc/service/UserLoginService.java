package com.lyc.service;

import com.lyc.domain.ResponseResult;
import com.lyc.domain.User;

public interface UserLoginService {

    ResponseResult login(User user);

    ResponseResult logOut();
}
