package com.example.shiro.exception;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @Author jiang
 * @Date 2019/8/22 10:04
 */
@RestControllerAdvice
public class NoPermissionException {
    @ExceptionHandler(UnauthorizedException.class)
    public String handleShiroException(Exception ex) {
        return "无权限";
    }
    @ExceptionHandler(AuthorizationException.class)
    public String AuthorizationException(Exception ex) {
        return "权限认证失败";
    }
}
