package eu.merloteducation.didservice;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import eu.merloteducation.didservice.repositories.ParticipantCertificateRepository;
import eu.merloteducation.didservice.service.DidServiceImpl;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    void generateDidAndPrivateKeyCorrectly() {

        String didRegex = "did:web:" + merlotDomain.replace(".", "\\.") + "#[-A-Za-z0-9]*";

        ParticipantDidPrivateKeyCreateRequest request = new ParticipantDidPrivateKeyCreateRequest();
        request.setIssuer("foo");
        request.setSubject("bar");

        ParticipantDidPrivateKeyDto dto = didService.generateDidAndPrivateKey(request);

        assertTrue(dto.getDid().matches(didRegex));

        String privateKey = dto.getPrivateKey();
        assertTrue(privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(privateKey.endsWith("-----END PRIVATE KEY-----\n"));

        verify(certificateRepository).save(certificateArgumentCaptor.capture());
        ParticipantCertificate cert = certificateArgumentCaptor.getValue();

        assertTrue(cert.getDid().matches(didRegex));

        String certificate = cert.getCertificate();
        assertTrue(certificate.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(certificate.endsWith("-----END CERTIFICATE-----\n"));
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
}
