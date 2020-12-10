package chinobot.security3.controller;

import chinobot.security3.common.security.utils.JWTUtils;
import chinobot.security3.entity.User;
import chinobot.security3.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;


@Controller
@RequestMapping("/")
public class LoginController {

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    private UserService userService ;

    @Autowired
    protected AuthenticationManager authenticationManager;


    @GetMapping("/login")
    public String login(){
        return "login";
    }


    @PostMapping("/login2")
    public String login2(String username,String password){

        try{

            UserDetails user=userService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user, password,user.getAuthorities());
            //Authentication authentication =
            //        authenticationManagerBuilder.getObject().authenticate(authenticationToken);



            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        catch (Exception ex){
            ex.printStackTrace();
            return "login";
        }
        return "index";

    }

    @PostMapping("/jwtlogin")
    @ResponseBody
    public Object jwtlogin(@RequestBody User user){
        String username=user.getUsername();
        String password=user.getPassword();
        try{

            //UserDetails user=userService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, password);
            //,user.getAuthorities());
            //Authentication authentication =
            //        authenticationManagerBuilder.getObject().authenticate(authenticationToken);

            Authentication authentication=authenticationManager.authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String token = JWTUtils.createToken((User)authentication.getPrincipal());
            // 返回 token 与 用户信息
            Map<String,Object> authInfo = new HashMap<String,Object>(2);
            authInfo.put("token",token);
            authInfo.put("user", authentication.getPrincipal());

            return authInfo;
        }
        catch (Exception ex){
            ex.printStackTrace();
            return "登陆失败"+ex.getMessage();
        }


    }

    @RequestMapping("/index")
    public String index(){
        return "index";

    }

    @RequestMapping("/")
    public String index2(){
        return "index";

    }

    @RequestMapping("/mypage")
    @ResponseBody
    public Object mypage(){
        return "你好,首页";

    }

    @RequestMapping("/admin")
    public String admin(){
        return "admin";

    }

}
