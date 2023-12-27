package com.example.security.user;


import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter // getPassword 오버라이드
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "tb_user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public User(String firstname,String lastname,String email,String password,Role role){
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    // 계정의 권한 목록 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    // 계정의 고유한 값을 반환 (ex) 중복값이 없는 이메일 값)
    @Override
    public String getUsername() {
        return email;
    }

    // 계정의 만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        return true; // 만료 안됨.
    }


    // 계정의 잠김 여부 반환
    @Override
    public boolean isAccountNonLocked() {
        return true; // 잠기지 않음.
    }

    // 비밀번호 만료 여부 반환
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 만료 안됨.
    }

    // 계정의 활성화 여부 반환
    @Override
    public boolean isEnabled() {
        return true; // 활성화 됨.
    }
}
