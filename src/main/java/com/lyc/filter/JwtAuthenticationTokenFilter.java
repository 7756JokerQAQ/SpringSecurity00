package com.lyc.filter;

import com.lyc.domain.LoginUser;
import com.lyc.provider.JwtProperties;
import com.lyc.provider.JwtProvider;
import com.lyc.utils.RedisCache;
import io.netty.util.internal.StringUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JWT过滤器通过校验请求头token进行自动登录...");
        //先拿到Authorization请求头部信息
        String authToken = jwtProvider.getToken(request);
        // 判断一下内容是否为空
        if (!StringUtil.isNullOrEmpty(authToken) && authToken.startsWith(jwtProperties.getTokenPrefix())) {
            //去掉token的前缀拿到真是的token
            authToken = authToken.substring(jwtProperties.getTokenPrefix().length());
            //接着拿到token里面的登录账号
            String loginAccount = jwtProvider.getSubjectFromToken(authToken);
            if (!StringUtil.isNullOrEmpty(loginAccount) && SecurityContextHolder.getContext().getAuthentication() == null) {
                //查询用户
                LoginUser loginUser = redisCache.getCacheObject("login");
                //拿到用户的信息验证用户的信息与token
                if (jwtProvider.validateToken(authToken, loginUser)) {
                    // 组装authentication对象，构造参数是Principal Credentials 与 Authorities
                    // 后面的拦截器里面会用到 grantedAuthorities 方法
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(loginUser, loginUser.getPassword(), loginUser.getAuthorities());
                    // 将authentication信息放入到上下文对象中
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("JWT过滤器通过校验请求头token自动登录成功, user : {}", loginUser.getUsername());
                } else {
                    log.info("缓存已经删除或者缓存已过期!");
                }
            }

        } else {
            log.info("token为空或者token格式不正确");
        }

        //如果为空直接放行
        filterChain.doFilter(request, response);
    }
}
