package jaas;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

public class JaasFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String jaas_conf = filterConfig.getServletContext().getRealPath("/WEB-INF/jaas.config");
        System.getProperties().setProperty("java.security.auth.login.config",jaas_conf);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        // Если в реквесте уже есть Principal - ничего не делаем
        if (req.getUserPrincipal() != null ) {
            chain.doFilter(request, response);
        }

        // Получаем security Header. А если его нет - запрашиваем
        String secHeader = req.getHeader("authorization");
        if (secHeader == null) {
            requestNewAuthInResponse(response);
        }// Проверяем аутентификацию
        else {
            String authorization = secHeader.replace("Basic ", "");
            Base64.Decoder decoder = java.util.Base64.getDecoder();
            authorization = new String(decoder.decode(authorization));
            String[] loginData = authorization.split(":");
            try {
                if (loginData.length == 2) {
                    req.login(loginData[0], loginData[1]);
                    chain.doFilter(request, response);
                } else {
                    requestNewAuthInResponse(response);
                }
            } catch (ServletException e) {
                requestNewAuthInResponse(response);
            }
        }
    }

    @Override
    public void destroy() {

    }

    private void requestNewAuthInResponse(ServletResponse response) throws IOException {
        HttpServletResponse resp = (HttpServletResponse) response;
        String value = "Basic realm=\"JaasLogin\"";
        resp.setHeader("WWW-Authenticate", value);
        resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
