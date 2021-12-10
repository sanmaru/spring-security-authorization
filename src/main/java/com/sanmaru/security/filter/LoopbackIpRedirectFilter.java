package com.sanmaru.security.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

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
        CsrfToken token = new HttpSessionCsrfTokenRepository().loadToken(request);
        if (token != null) {
            logger.info("======= " + "CsrfToken : " + token.getToken());
        }
//        if (request.getServerName().equals("localhost") && request.getHeader("host") != null) {
//            UriComponents uri = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
//                    .host("127.0.0.1").build();
//            filterChain.doFilter(request, response);
//            response.sendRedirect(uri.toUriString());
//        }
        filterChain.doFilter(request, response);
    }

}