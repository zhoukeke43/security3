package chinobot.security3.common.security.utils;

import chinobot.security3.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {

    public static User getCurrentUser(){


        if(!SecurityContextHolder.getContext().getAuthentication().getName().equals("anonymousUser")){
            //已登录
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();//获取用户信息

            //获取登录的用户名
            String username = authentication.getName();
            System.out.println("username : "+username);

            //用户的所有权限
            //Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            //System.out.println("authorities : "+authorities);


            /**
             * 如果要获取更详细的用户信息可以采用下面这种方法
             */
            //用户的基本信息
            User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            return user;
        }else{
            //未登录
            return null;
        }

    }

}
