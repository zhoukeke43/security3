package chinobot.security3.common.security.config;

import chinobot.security3.common.security.component.EmailCodeAuthentictionProvider;
import chinobot.security3.common.security.component.MyAuthenticationFailHandler;
import chinobot.security3.common.security.component.MyAuthenticationSuccessHandler;
import chinobot.security3.common.security.filter.EmailCodeAuthenticationFilter;
import chinobot.security3.common.security.filter.JWTFilter;
import chinobot.security3.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserService userService;

    @Autowired
    private  EmailCodeAuthenticationSecurityConfig emailCodeAuthenticationSecurityConfig;

    @Autowired
    private MyAuthenticationFailHandler myAuthenticationFailHandler;

    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;



    @Bean
    public PasswordEncoder passwordEncoder() {
        // 密码加密方式
        //return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        http.headers().frameOptions().disable();

        http.csrf().disable();


        http .authorizeRequests()
                    .antMatchers("/jwtlogin").permitAll()
                    .antMatchers("/login2").permitAll()
                    .antMatchers("/","/index").hasAnyRole("public","admin","ROLE_admin")
                    .antMatchers("/admin").hasRole("admin")
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    //.loginProcessingUrl("/auth/login2")
                    .permitAll()
                    .and()
                .logout()//开启注销功能
                    //.logoutSuccessUrl("/login")//注销后跳转到哪一个页面
                    //.logoutUrl("/logout") // 配置注销登录请求URL为"/logout"（默认也就是 /logout）
                    //.clearAuthentication(true) // 清除身份认证信息
                    //.invalidateHttpSession(true) //使Http会话无效
                    .permitAll()// 允许访问登录表单、登录接口
                    .and();
                //.addFilterBefore(new UsernamePasswordAuthenticationFilter(),UsernamePasswordAuthenticationFilter.class);
        //http.apply(emailCodeAuthenticationSecurityConfig);


        //myAuthenticationFailHandler.setTar("email");
        EmailCodeAuthenticationFilter filter = new EmailCodeAuthenticationFilter(new AntPathRequestMatcher("/account/login/email","POST")) ;
        filter .setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        filter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(myAuthenticationFailHandler);


        EmailCodeAuthentictionProvider provider = new EmailCodeAuthentictionProvider(userService) ;
        http.authenticationProvider(provider)
                .addFilterAfter(filter , UsernamePasswordAuthenticationFilter.class);

        JWTFilter customFilter = new JWTFilter();
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        /*auth.inMemoryAuthentication()
                .withUser("user").password("123").roles("USER")
                .and()
                .withUser("admin").password("123").roles("USER","ADMIN");*/

        auth.userDetailsService(userService);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().antMatchers("/css/*","/js/*","/font/*","/images/*");
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /*
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password").roles("USER");
    }
    */
}
