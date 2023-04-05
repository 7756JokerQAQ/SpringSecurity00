package com.lyc;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.lyc.domain.User;
import com.lyc.mapper.MenuMapper;
import com.lyc.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

@SpringBootTest
public class MapperTest {
    @Autowired
    private UserMapper userMapper;

    @Autowired
    private MenuMapper menuMapper;

    @Test
    void testUserMapper() {

        QueryWrapper<com.lyc.domain.User> userQueryWrapper = new QueryWrapper<>();
        QueryWrapper<com.lyc.domain.User> id = userQueryWrapper.eq("id", 2);

        List<User> users = userMapper.selectList(id);
        System.out.println(users);
    }

    @Test
    void testSelectUserMapperById(){
        System.out.println(menuMapper.selectPermsByUserId(2L));
    }


    @Test
    void passwordEncoder() {
        BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
        //加密的方法
        String encode = passwordEncoder.encode("1234");
        String encode1 = passwordEncoder.encode("1234");
        UpdateWrapper<User> updateWrapper=new UpdateWrapper<>();
        updateWrapper.eq("id",2).set("password",encode1);

        userMapper.update(null,updateWrapper);
        System.out.println(passwordEncoder.matches("1234",encode1));
      //  System.out.println(encode);
       // System.out.println(encode1);
    }
}
