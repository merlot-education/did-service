package eu.merloteducation.didservice;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import eu.merloteducation.didservice.repositories.ParticipantCertificateRepository;
import eu.merloteducation.didservice.service.DidServiceImpl;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@EnableConfigurationProperties
public class DidServiceTests {
    @Value("${merlot-domain}")
    private String merlotDomain;

    @Autowired
    private DidServiceImpl didService;

    @MockBean
    private ParticipantCertificateRepository certificateRepository;

    @Captor
    private ArgumentCaptor<ParticipantCertificate> certificateArgumentCaptor;

    @BeforeEach
    public void setUp() {

        ReflectionTestUtils.setField(didService, "certificateRepository", certificateRepository);
    }

    @Test
    void generateDidAndPrivateKeyCorrectly() throws IOException, CertificateException {

        String didRegex = "did:web:" + merlotDomain + "#[-A-Za-z0-9]*";

        ParticipantDidPrivateKeyCreateRequest request = new ParticipantDidPrivateKeyCreateRequest();
        request.setIssuer("foo");
        request.setSubject("bar");

        ParticipantDidPrivateKeyDto dto = didService.generateDidAndPrivateKey(request);

        assertTrue(dto.getDid().matches(didRegex));

        String privateKeyString = dto.getPrivateKey();
        assertTrue(privateKeyString.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(privateKeyString.endsWith("-----END PRIVATE KEY-----\n"));

        PrivateKey privateKey = convertToPrivateKey(privateKeyString);
        assertNotNull(privateKey);

        verify(certificateRepository).save(certificateArgumentCaptor.capture());
        ParticipantCertificate cert = certificateArgumentCaptor.getValue();

        assertTrue(cert.getDid().matches(didRegex));

        String certificateString = cert.getCertificate();
        assertTrue(certificateString.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(certificateString.endsWith("-----END CERTIFICATE-----\n"));

        List<X509Certificate> certificates = convertToCertficates(certificateString);
        assertEquals(1, certificates.size());
    }

    @Test
    void getCertificateCorrectly() {

        String expected = "-----BEGIN CERTIFICATE-----\nbaaaAaAAaaaRrr\n-----END CERTIFICATE-----\n";

        when(certificateRepository.findByDid(any())).thenReturn(expected);

        String actual = didService.getCertificate("foo");
        assertEquals(expected, actual);
    }

    @Test
    void getDidDocumentCorrectly() {

    }

    private PrivateKey convertToPrivateKey(String prk) throws IOException {

        PEMParser pemParser = new PEMParser(new StringReader(prk));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
        return converter.getPrivateKey(privateKeyInfo);
    }

    private List<X509Certificate> convertToCertficates(String certs) throws CertificateException {

        ByteArrayInputStream certStream = new ByteArrayInputStream(certs.getBytes(StandardCharsets.UTF_8));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (List<X509Certificate>) certFactory.generateCertificates(certStream);
    }
}
