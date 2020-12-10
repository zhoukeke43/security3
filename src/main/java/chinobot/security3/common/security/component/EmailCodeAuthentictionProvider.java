package chinobot.security3.common.security.component;

import chinobot.security3.service.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class EmailCodeAuthentictionProvider implements AuthenticationProvider {

    UserService userService ;
    public EmailCodeAuthentictionProvider(UserService userService) {
        this.userService = userService;
    }

    /**
     * 认证
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        EmailCodeAuthenticationToken token = (EmailCodeAuthenticationToken)authentication;
        UserDetails user = userService.getByEmail((String)token.getPrincipal());
        System.out.println(token.getPrincipal());
        if(user == null){
            System.out.println("无法获取用户信息");
            throw new InternalAuthenticationServiceException("无法获取用户信息");
        }
        System.out.println(user.getAuthorities());

        UsernamePasswordAuthenticationToken result =
                new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
                /*
                Details 中包含了 ip地址、 sessionId 等等属性
                */
        //mailCodeAuthenticationToken result=new EmailCodeAuthenticationToken(user.getAuthorities(),token.getPrincipal());
        result.setDetails(token.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> aClass) {

        return EmailCodeAuthenticationToken.class.isAssignableFrom(aClass);
    }



}
