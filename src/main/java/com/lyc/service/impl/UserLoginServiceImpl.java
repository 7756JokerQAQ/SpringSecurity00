package com.lyc.service.impl;

import com.lyc.bo.AccessToken;
import com.lyc.domain.LoginUser;
import com.lyc.domain.ResponseResult;
import com.lyc.domain.User;
import com.lyc.provider.JwtProperties;
import com.lyc.provider.JwtProvider;
import com.lyc.service.UserLoginService;
import com.lyc.utils.JwtUtil;
import com.lyc.utils.RedisCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Service
public class UserLoginServiceImpl implements UserLoginService {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    private RedisCache redisCache;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private JwtProperties jwtProperties;

    @Override
    public ResponseResult login(User user) {
        log.debug("进入login方法");
        //1.创建UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken usernameAuthentication = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        //2.认证
        //authenticationManager接口调用authenticate方法，方法返回的是Authentication对象，需要Authentication类型的参数。
        //Authentication是接口，使用这个接口的实现类来把用户的账号密码封装成这个类型的参数。供authenticationManager接口的authenticate方法调用
        Authentication authenticate = authenticationManager.authenticate(usernameAuthentication);
        //如果查询不到用户，就抛出异常
        if (Objects.isNull(authenticate)) {
            throw new RuntimeException("登录失败!");
        }
        //保存认证信息
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        //自定义生成token
        AccessToken accessToken = jwtProvider.createToken((UserDetails) authenticate.getPrincipal());

        //把authenticate对象强转为LoginUser对象
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        System.out.println(loginUser.toString());
        redisCache.setCacheObject("login", loginUser);
        //把token响应给前端
        Map<String, String> map = new HashMap<>();
        map.put(jwtProperties.getRequestHeader(), accessToken.getToken());
        return new ResponseResult(200, "登入成功", map);
    }

    @Override
    public ResponseResult logOut() {
        //直接去缓存中删除对应的缓存信息就可以了
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        redisCache.deleteObject("login");
        return new ResponseResult(200,"注销成功");
    }
}
