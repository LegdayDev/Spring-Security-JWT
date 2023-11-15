package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * <h2>PrincipalDetailsService 동작 원리</h2>
 * <p>
 *     http://localhost:8080/login 요청 시 PrincipalDetailsService 실행
 *     하지만 Security 설정에서 formLogin 을 disable 했기 때문에 /login 에서 동작안함.
 *     <li>즉, 필터에서 동작하도록 해야함 </li>
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("PrincipalDetailsService 진입");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
