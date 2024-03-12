package eu.merloteducation.didservice.config;

import org.springframework.context.annotation.Configuration;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Configuration
public class SecurityConfig {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
