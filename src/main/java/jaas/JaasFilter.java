package jaas;

import javax.servlet.*;
import java.io.IOException;

public class JaasFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String jaas_conf = filterConfig.getServletContext().getRealPath("/WEB-INF/jaas.config");
        System.getProperties().setProperty("java.security.auth.login.config",jaas_conf);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

    }

    @Override
    public void destroy() {

    }
}
