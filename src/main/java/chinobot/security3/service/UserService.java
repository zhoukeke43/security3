package chinobot.security3.service;

import chinobot.security3.entity.Role;
import chinobot.security3.entity.User;
import chinobot.security3.mapper.UserMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class UserService extends ServiceImpl<UserMapper, User> implements UserDetailsService {


    @Autowired
    RoleService roleService;




    public UserDetails getByEmail(String email) throws UsernameNotFoundException {

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("email", email);
        User user = this.getOne(queryWrapper);
        if (user == null) {
            System.out.println("无法获取用户信息");
            throw new UsernameNotFoundException("该用户不存在！");
        } else {

            List<Role> roles = roleService.getByUserId(user.getId());
            user.setRoles(roles);
            return user;
        }

    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("username", username);
        User user = this.getOne(queryWrapper);
        if (user == null) {
            throw new UsernameNotFoundException("该用户不存在！");
        } else {

            List<Role> roles = roleService.getByUserId(user.getId());
            user.setRoles(roles);
            return user;
        }

    }
}
