package jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JaasLoginModule implements LoginModule {

    private CallbackHandler callbackHandler;
    private Subject subject;
    private String login;
    private List<String> userGroups;
    private UserPrincipal userPrincipal;
    private RolePrincipal rolePrincipal;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.callbackHandler = callbackHandler;
        this.subject = subject;
    }

    @Override
    public boolean login() throws LoginException {
        // Добавляем колбэки
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("login");
        callbacks[1] = new PasswordCallback("password", true);
        // При помощи колбэков получаем через CallbackHandler логин и пароль
        try {
            callbackHandler.handle(callbacks);
            String name = ((NameCallback) callbacks[0]).getName();
            String password = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());
            // Далее выполняем валидацию.
            // Тут просто для примера проверяем определённые значения
            if (name != null && name.equals("user123") && password != null && password.equals("pass123")) {
                // Сохраняем информацию, которая будет использована в методе commit
                // Не "пачкаем" Subject, т.к. не факт, что commit выполнится
                // Для примера проставим группы вручную, "хардкодно".
                login = name;
                userGroups = new ArrayList<String>();
                userGroups.add("admin");
                return true;
            } else {
                throw new LoginException("Authentication failed");
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException(e.getMessage());
        }
    }

    @Override
    public boolean commit() throws LoginException {
        userPrincipal = new UserPrincipal(login);
        subject.getPrincipals().add(userPrincipal);
        if (userGroups != null && userGroups.size() > 0) {
            for (String groupName : userGroups) {
                rolePrincipal = new RolePrincipal(groupName);
                subject.getPrincipals().add(rolePrincipal);
            }
        }
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().remove(userPrincipal);
        subject.getPrincipals().remove(rolePrincipal);
        return true;
    }
}
