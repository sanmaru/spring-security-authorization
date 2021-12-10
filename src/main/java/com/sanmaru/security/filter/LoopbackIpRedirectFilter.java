package com.sanmaru.security.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoopbackIpRedirectFilter extends OncePerRequestFilter {

    final static Logger logger = LoggerFactory.getLogger(LoopbackIpRedirectFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("================LoopbackIpRedirectFilter : "
                + request.getMethod() + " "
                + request.getRequestURI()
                + ( request.getQueryString() != null ? "?" + request.getQueryString() : "" ));
        filterChain.doFilter(request, response);
    }

}