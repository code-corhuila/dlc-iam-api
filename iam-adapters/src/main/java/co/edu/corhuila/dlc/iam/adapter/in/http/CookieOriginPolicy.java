package co.edu.corhuila.dlc.iam.adapter.in.http;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class CookieOriginPolicy {
    private final String allowedOrigin;

    public CookieOriginPolicy(@Value("${IAM_AUTH_ALLOWED_ORIGIN}") String allowedOrigin) {
        if (allowedOrigin == null || allowedOrigin.isBlank() || allowedOrigin.contains("*")) {
            throw new IllegalArgumentException("An exact Auth Origin is required");
        }
        this.allowedOrigin = allowedOrigin;
    }

    public boolean allows(String origin, String fetchSite) {
        if (fetchSite != null && !fetchSite.equals("same-origin")
            && !fetchSite.equals("same-site")) return false;
        return allowedOrigin.equals(origin)
            || (origin == null && "same-origin".equals(fetchSite));
    }
}
