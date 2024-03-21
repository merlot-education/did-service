package eu.merloteducation.didservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.merloteducation.didservice.models.did.DidDocument;
import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import eu.merloteducation.didservice.repositories.ParticipantCertificateRepository;
import eu.merloteducation.didservice.service.DidServiceImpl;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@EnableConfigurationProperties
public class DidServiceTests {
    @Value("${did-domain}")
    private String didDomain;

    @Value("${certificate-issuer}")
    private String certificateIssuer;

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
    void generateDidAndPrivateKeyCorrectly() throws Exception {

        String didRegex = "did:web:" + didDomain.replaceFirst(":", "%3A") + ":participant:[-A-Za-z0-9]*";

        ParticipantDidPrivateKeyCreateRequest request = new ParticipantDidPrivateKeyCreateRequest();
        request.setSubject("ABC Company");

        ParticipantDidPrivateKeyDto dto = didService.generateDidAndPrivateKey(request);

        assertTrue(dto.getDid().matches(didRegex));
        System.out.println(dto.getVerificationMethod());
        assertTrue(dto.getVerificationMethod().matches(didRegex + "#JWK2020"));

        String privateKeyString = dto.getPrivateKey();
        assertTrue(privateKeyString.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(privateKeyString.endsWith("-----END PRIVATE KEY-----\n"));

        PrivateKey privateKey = convertPemStringToPrivateKey(privateKeyString);
        assertNotNull(privateKey);

        verify(certificateRepository).save(certificateArgumentCaptor.capture());
        ParticipantCertificate cert = certificateArgumentCaptor.getValue();

        assertTrue(cert.getDid().matches(didRegex));

        String certificateString = cert.getCertificate();
        assertTrue(certificateString.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(certificateString.endsWith("-----END CERTIFICATE-----\n"));

        List<X509Certificate> certificates = convertPemStringToCertificates(certificateString);
        assertEquals(1, certificates.size());

        X509Certificate certificate = certificates.stream().findFirst().orElse(null);
        assertNotNull(certificate);
        assertEquals("CN=" + certificateIssuer, certificate.getIssuerX500Principal().getName());
        assertEquals("CN=ABC Company", certificate.getSubjectX500Principal().getName());
    }

    @Test
    void getCertificateCorrectly() throws Exception {

        ParticipantCertificate participantCertificate = getTestParticipantCertificate();
        when(certificateRepository.findByDid(any())).thenReturn(participantCertificate);

        String actual = didService.getCertificate("foo");
        assertEquals(participantCertificate.getCertificate(), actual);
    }

    @Test
    void getDidDocumentCorrectly() throws Exception {

        ObjectMapper mapper = new ObjectMapper();

        String expectedJsonString = getTestDidDocumentJsonString();
        DidDocument expected = mapper.readValue(expectedJsonString, DidDocument.class);

        ParticipantCertificate participantCertificate = getTestParticipantCertificate();
        when(certificateRepository.findByDid(any())).thenReturn(participantCertificate);

        String actualJsonString = didService.getDidDocument("foo");
        DidDocument actual = mapper.readValue(actualJsonString, DidDocument.class);

        assertThat(actual).usingRecursiveComparison().isEqualTo(expected);
    }

    private ParticipantCertificate getTestParticipantCertificate() {

        ParticipantCertificate participantCertificate = new ParticipantCertificate();
        participantCertificate.setDid(
            "did:web:marketplace.dev.merlot-education.eu:participant:46fa1bd9-3eb6-492f-84a0-5f78a42065b3");
        participantCertificate.setCertificate("""
            -----BEGIN CERTIFICATE-----
            MIIEtzCCAp+gAwIBAgIGAY5CEUc6MA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMM
            B0tpbSBDaGkwIBcNMjQwMzE1MTIyMzMyWhgPMjEyNDAzMTUxMjIzMzJaMBAxDjAM
            BgNVBAMMBUtyYWxsMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3/Hw
            LTX3Piivk3FUnOletWKYSRWSPqmHZz+DiSylZ7nMh+Bkmh/xjvNkXn3Kj2Ay5N3f
            4jb4Ph3Swd5jy+QZHvFjyOzNS+c1Z2KHV7Yw65xeA4a9oZ/4ZYpoSYF3m92o66O5
            vUQHNgxzob0nJQtILH+xtAjdcodFkUsoLV/h4/gy255cvHTxdsiW+wiIjFABqoNv
            0lBDqcDZwr7BXtYFy3QHAPPTYn4QD6/1YPYsVqAoQcHHwszQainxPSLcWNXZMrKo
            rM6JEqWQ/K6YiFI3Ek+W2oHgX3YQJd+sxCFy4c7iBgu7HrePLZOr2rDNijBJw6aB
            xdp2zCpmCH5f0wUz/D849mfWcXM9dCCZ7upR6XKSxlx3D5+K+t9rJeRbqDwj5ljj
            oy/zSEc3ef01U1K0AnI7rjjzXSYscht5QAbsJ5mrg4YG3RMdFGSRAmSVo151NHm9
            sfr9mtIszT+0rESMApDz5Lu/2mMgKLrotSpxe92KkNLvM+wswRGN13xu9JcNVtKO
            2f+pf10JTxNFj5/WE7EOUcn+qr7c86OIQZqWUIoUlsf7ugRN1QQAKccW2ITLI119
            Ua8YD6SrR3hmWT1fS41x3L0Xyep38r9qHxxZU5qCuVhzEUjk2utErT6jBLb9Hmrr
            fO5ErGVyZOvRxB8+UBzemY7IBy8cv55KpF+arOMCAwEAAaMTMBEwDwYDVR0TAQH/
            BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAjX6yEnMdLpXSODLmOSlMR7vbT9q8
            mo5d+uM168c9rXfAplGOsPem7ASCZNE1dCh+9C5QcCXsdP57ELBl2HMJAxS3QoVr
            aYHUaNXB22drV6oFnWC7bpLT2DbPvCN9IeibqezMdbmtQBj6ufj5nQOO2haT2iuB
            iuc0KR0L7sdTeERjNpIxAmf6VukPVHmgDysRBDR+PurJ1+B3mp/Zejgn6fCAMn92
            0Ji2tg3KjDGKbb7Cj1wRmNBjjPoyXhn7DLexIUnSg7GOEvOP3kFldjzVagnruKiS
            S0tUxh0UaZ/AuV4qvROzP2DiTO5G3UT/8wkrvoygAv+m9T49CIFzC4quS3+t26Ng
            I/VQI+tnqnaTH87JV4zPvlA95++W56dC3V3T3sKtmn3NWT/9IP4I7Vy0MqY/O/Bg
            bOYob5hJS6cYrWxrdfPuvSHF/5WRvJ9YdygGWOdesJiKal/3iaZRUK4vbohHwqkU
            nR+zog2sx0MFMHsPxGug3CPDXc4B5BCnMlGQhkZlmU3Ig/vdXwy3+lnkE1yO+lkW
            s8F4XkZgw53kvVmWAUYqJwWHe0WXW1XP0a3PynWQe2+Y2M9M2Qd1FhexQeNfVjXs
            jXVnDHKAyUVc0wYlUfdNBG0llCmFDSfSkyhFfCBAukjNyJpgdW1m8QGc5+q6CTAE
            mdUr25dOswgYHwQ=
            -----END CERTIFICATE-----""");
        return participantCertificate;
    }

    private String getTestDidDocumentJsonString() {

        return """
            {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": "did:web:marketplace.dev.merlot-education.eu:participant:46fa1bd9-3eb6-492f-84a0-5f78a42065b3",
                "verificationMethod": [
                    {
                        "@context": [
                            "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/"
                        ],
                        "id": "did:web:marketplace.dev.merlot-education.eu:participant:46fa1bd9-3eb6-492f-84a0-5f78a42065b3#JWK2020",
                        "type": "JsonWebKey2020",
                        "controller": "did:web:marketplace.dev.merlot-education.eu:participant:46fa1bd9-3eb6-492f-84a0-5f78a42065b3",
                        "publicKeyJwk": {
                            "kty": "RSA",
                            "n": "AN_x8C019z4or5NxVJzpXrVimEkVkj6ph2c_g4kspWe5zIfgZJof8Y7zZF59yo9gMuTd3-I2-D4d0sHeY8vkGR7xY8jszUvnNWdih1e2MOucXgOGvaGf-GWKaEmBd5vdqOujub1EBzYMc6G9JyULSCx_sbQI3XKHRZFLKC1f4eP4MtueXLx08XbIlvsIiIxQAaqDb9JQQ6nA2cK-wV7WBct0BwDz02J-EA-v9WD2LFagKEHBx8LM0Gop8T0i3FjV2TKyqKzOiRKlkPyumIhSNxJPltqB4F92ECXfrMQhcuHO4gYLux63jy2Tq9qwzYowScOmgcXadswqZgh-X9MFM_w_OPZn1nFzPXQgme7qUelyksZcdw-fivrfayXkW6g8I-ZY46Mv80hHN3n9NVNStAJyO644810mLHIbeUAG7CeZq4OGBt0THRRkkQJklaNedTR5vbH6_ZrSLM0_tKxEjAKQ8-S7v9pjICi66LUqcXvdipDS7zPsLMERjdd8bvSXDVbSjtn_qX9dCU8TRY-f1hOxDlHJ_qq-3POjiEGallCKFJbH-7oETdUEACnHFtiEyyNdfVGvGA-kq0d4Zlk9X0uNcdy9F8nqd_K_ah8cWVOagrlYcxFI5NrrRK0-owS2_R5q63zuRKxlcmTr0cQfPlAc3pmOyAcvHL-eSqRfmqzj",
                            "e": "AQAB",
                            "alg": "PS256",
                            "x5u": "https://marketplace.dev.merlot-education.eu/participant/46fa1bd9-3eb6-492f-84a0-5f78a42065b3/cert.pem"
                        }
                    }
                ]
            }""";
    }

    private PrivateKey convertPemStringToPrivateKey(String prk) throws IOException {

        PEMParser pemParser = new PEMParser(new StringReader(prk));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
        return converter.getPrivateKey(privateKeyInfo);
    }

    @SuppressWarnings("unchecked")
    private List<X509Certificate> convertPemStringToCertificates(String certs) throws CertificateException {

        ByteArrayInputStream certStream = new ByteArrayInputStream(certs.getBytes(StandardCharsets.UTF_8));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (List<X509Certificate>) certFactory.generateCertificates(certStream);
    }
}
