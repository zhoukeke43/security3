package chinobot.security3.common.security.filter;

import chinobot.security3.common.security.utils.JWTUtils;
import chinobot.security3.entity.User;
import chinobot.security3.service.UserService;
import com.auth0.jwt.interfaces.Claim;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JWT过滤器，拦截 /secure的请求
 */
public class JWTFilter extends GenericFilterBean {



    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        response.setCharacterEncoding("UTF-8");
        //获取 header里的token
        final String token = request.getHeader("authorization1");

        if ("OPTIONS".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            chain.doFilter(request, response);
        }
        else if(request.getRequestURI().endsWith("jwtlogin")){
            response.setStatus(HttpServletResponse.SC_OK);
            chain.doFilter(request, response);
        }
        // Except OPTIONS, other request should be checked by JWT
        else {

            if (token == null) {
                response.getWriter().write("没有token！");
                return;
            }

            Map<String, Claim> userData = JWTUtils.verifyToken(token);
            if (userData == null) {
                response.getWriter().write("token不合法！");
                return;
            }
            //Integer id = userData.get("id").asInt();
            //String name = userData.get("name").asString();
            String username = userData.get("username").asString();
            User user=new User();
            user.setUsername(username);

            List<GrantedAuthority> authorities =
                    AuthorityUtils.createAuthorityList("ROLE_admin");
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user, "",authorities);

            //拦截器 拿到用户信息，放到request中
            //request.setAttribute("id", id);
            //request.setAttribute("name", name);
            //request.setAttribute("username", username);


            //,user.getAuthorities());
            //Authentication authentication =
            //        authenticationManagerBuilder.getObject().authenticate(authenticationToken);

            //Authentication authentication=authenticationManager.authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            //String token = JWTUtils.createToken((User)authentication.getPrincipal());
            // 返回 token 与 用户信息


            chain.doFilter(req, res);
        }
    }

    @Override
    public void destroy() {
    }
}