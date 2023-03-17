package com.sha.springbootbookseller.security;

import com.sha.springbootbookseller.model.User;
import com.sha.springbootbookseller.service.IUserService;
import com.sha.springbootbookseller.util.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private IUserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        User user = userService.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
      ;
        Set<GrantedAuthority> authorities = Set.of(SecurityUtils.convertToAuthority(user.getRole().name()));

        return UserPrincipal.builder()
                .user(user).id(user.getId())
                .username(username)
                .password(user.getPassword())
                .authorities(authorities)
                .build();


        /*
        try {
            User user = userService.findByUsername(username);

            if(user == null){
                System.out.println("User not found with the provided username" + user.toString());
                return null;
            }
            System.out.println("User from username " + user.toString());
            return new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    );

        } catch (Exception e){
            throw new UsernameNotFoundException("User not found");
        }

        */
    }
}
