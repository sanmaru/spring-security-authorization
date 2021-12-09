package com.sanmaru.security.mfa.custom;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.Collection;

@Entity
@Table (name="users")
public class CustomUser {

    private String username;

    private String password;

    private String mfa;

    private String secret;

    private String enabled;

    public CustomUser(String username, String password, String mfa, String secret, String enabled) {
        this.username = username;
        this.password = password;
        this.mfa = mfa;
        this.secret = secret;
        this.enabled = enabled;
    }

    public CustomUser(CustomUser customUser) {
        this.username = customUser.getUsername();
        this.password = customUser.getPassword();
        this.mfa = customUser.getMfa();
        this.secret = customUser.getSecret();
        this.enabled = customUser.getEnabled();
    }

    public CustomUser() {

    }

    @Id
    public String getUsername() { return username; }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() { return password; }

    public void setPassword(String passWord) {
        this.password = passWord;
    }

    public String getMfa() {
        return mfa;
    }

    public void setMfa(String mfa) {
        this.mfa = mfa;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getEnabled() {
        return enabled;
    }

    public void setEnabled(String enabled) {
        this.enabled = enabled;
    }
}
