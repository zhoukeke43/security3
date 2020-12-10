package chinobot.security3.service;

import chinobot.security3.entity.Role;
import chinobot.security3.mapper.RoleMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleService extends ServiceImpl<RoleMapper,Role> {
    List<Role> getByUserId(String userId){
        return baseMapper.getRolesByUserId(userId);
    }
}
