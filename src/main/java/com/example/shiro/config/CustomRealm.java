package com.example.shiro.config;

import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;


import java.util.HashSet;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm {
    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) SecurityUtils.getSubject().getPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> stringSet = new HashSet<>();
        //设置权限
        stringSet.add("user:show");
        stringSet.add("user:admin");
        info.setStringPermissions(stringSet);
        return info;
    }

    //这里唯一需要注意的是：你注册的加密方式和设置的加密方式还有Realm中身份认证的方式都是要一模一样的。
    //本文中的加密 ：MD5两次、salt=username+salt加密。
    //登录认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        //不加密的情况使用
        /*        System.out.println("-------身份认证方法--------");
        String userName = (String) authenticationToken.getPrincipal();
        String userPwd = new String((char[]) authenticationToken.getCredentials());
        //根据用户名从数据库获取密码
        String password = "123";
        String username = "test";
        if (!userName.equals(username)) {
            throw new AccountException("用户名不正确");
        } else if (!userPwd.equals(password)) {
            throw new AccountException("密码不正确");
        }
        return new SimpleAuthenticationInfo(userName, password, getName());*/

        //加密情况使用
        System.out.println("-------身份认证方法--------");

        String account2 = StringUtils.EMPTY;
        String password2 = StringUtils.EMPTY;

        if (authenticationToken instanceof UsernamePasswordToken) {
            UsernamePasswordToken token2 = (UsernamePasswordToken)authenticationToken;
             account2 = token2.getUsername();
             password2 = new String(token2.getPassword());
        }

        if (StringUtils.isBlank(account2)) {
            throw new IncorrectCredentialsException("account must not be blank");
        }
        if (StringUtils.isBlank(password2)) {
            throw new IncorrectCredentialsException("password must not be blank");
        }
        System.out.println(account2);
        System.out.println(password2);

        System.out.println("-------身份认证方法--------");
        String userName = (String) authenticationToken.getPrincipal();
        String userPwd = new String((char[]) authenticationToken.getCredentials());
        //根据用户名从数据库获取密码
        String password = "2415b95d3203ac901e287b76fcef640b";
        String username2 = "cj";
        if (!userName.equals(username2)) {
            throw new AccountException("用户名不正确");
        }
        //交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配
        return new SimpleAuthenticationInfo(userName, password,
                ByteSource.Util.bytes(userName + "salt"), getName());

    }

}

