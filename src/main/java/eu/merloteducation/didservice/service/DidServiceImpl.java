package eu.merloteducation.didservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.merloteducation.didservice.models.did.Did;
import eu.merloteducation.didservice.models.did.PublicJwk;
import eu.merloteducation.didservice.models.did.VerificationMethod;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import eu.merloteducation.didservice.repositories.ParticipantCertificateRepository;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
public class DidServiceImpl implements DidService {
    private static final String ALGORITHM = "RSA";

    private static final int KEY_SIZE = 4096;

    private final Logger logger = LoggerFactory.getLogger(DidService.class);

    @Autowired
    private ParticipantCertificateRepository certificateRepository;

    @Value("${merlot-domain}")
    private String merlotDomain;

    @Override
    public String getCertificate(String certId) {

        return certificateRepository.findByDid(certId);
    }

    @Override
    public String getDidDocument() {

        List<ParticipantCertificate> certificates = certificateRepository.findAll();

        return createDidDocument(merlotDomain, certificates);
    }

    /**
     * Generates a did:web, a key pair and certificate. Returns the did:web and private key and saves the certificate.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web and private key
     */
    @Override
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(ParticipantDidPrivateKeyCreateRequest request) {

        X509Certificate cert = null;
        KeyPair keyPair = null;

        String did = generateDidWeb();

        // The list of Relative Distinguished Names (RDN) forms the Distinguished Name (DN) of an issuer or a subject.
        // Common Name (CN) is currently the only RDN used here. Organization (O) and Country (C) could be added to the minimal list of RDNs.
        X500Name issuerName = new X500Name("CN=" + request.getIssuer());
        X500Name subjectName = new X500Name("CN=" + request.getSubject());

        keyPair = createKeyPair();

        assert keyPair != null;
        cert = createCertificate(issuerName, subjectName, keyPair);

        storeDidAndCertificate(did, cert);

        return createParticipantDidPrivateKeyDto(did, keyPair.getPrivate());
    }

    private String generateDidWeb() {

        String uuid = UUID.randomUUID().toString();
        return "did:web:" + merlotDomain + "#" + uuid;
    }

    private KeyPair createKeyPair() {

        KeyPairGenerator keyPairGenerator = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
        }

        return null;
    }

    private X509Certificate createCertificate(X500Name issuerName, X500Name subjectName, KeyPair keyPair) {

        X509Certificate cert = null;
        ContentSigner contentSigner = null;

        String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        BigInteger certSerialNumber = new BigInteger(
            Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 100); // <-- 100 Yr validity

        Date endDate = calendar.getTime();

        try {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            logger.error(e.getMessage(), e);
        }

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, certSerialNumber,
            startDate, endDate, subjectName, keyPair.getPublic());

        // Extensions --------------------------
        // Basic Constraints mark the certificate as a Certificate Authority (CA) certificate or an End Entity certificate.
        // A CA is allowed to sign other certificates.
        // An End Entity is e.g., a user or a server.
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
        try {
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true,
                basicConstraints); // Basic Constraints is usually marked as critical.
        } catch (CertIOException e) {
            logger.error(e.getMessage(), e);
        }
        // -------------------------------------

        try {
            cert = new JcaX509CertificateConverter().setProvider(Security.getProvider("BC"))
                .getCertificate(certBuilder.build(contentSigner));
        } catch (CertificateException e) {
            logger.error(e.getMessage(), e);
        }

        return cert;
    }

    private void storeDidAndCertificate(String did, X509Certificate certificate) {

        ParticipantCertificate cert = new ParticipantCertificate();
        cert.setDid(did);
        cert.setCertificate(convertCertificateToPemString(certificate));

        certificateRepository.save(cert);
    }

    private String convertCertificateToPemString(X509Certificate certificate) {

        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(certificate);
            pemWriter.close();
            return sw.toString();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

    private String convertPrivateKeyToPemString(PrivateKey privateKey) {

        try {
            StringWriter sw = new StringWriter();
            PemWriter pemWriter = new PemWriter(sw);
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.close();
            return sw.toString();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

    private ParticipantDidPrivateKeyDto createParticipantDidPrivateKeyDto(String did, PrivateKey privateKey) {

        ParticipantDidPrivateKeyDto dto = new ParticipantDidPrivateKeyDto();
        dto.setDid(did);
        dto.setPrivateKey(convertPrivateKeyToPemString(privateKey));

        return dto;
    }

    private String createDidDocument(String baseDomain, List<ParticipantCertificate> certificates) {

        String didWeb = "did:web:" + baseDomain;

        Did didDocument = new Did();
        didDocument.setContext(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"));
        didDocument.setId(didWeb);
        didDocument.setVerificationMethod(new ArrayList<>());
        didDocument.setAssertionMethod(new ArrayList<>());

        String vmContext = "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/";
        String type = "JsonWebKey2020";

        for (ParticipantCertificate certificateItem : certificates){
            VerificationMethod vm = new VerificationMethod();
            vm.setContext(List.of(vmContext));
            vm.setId(certificateItem.getDid());
            vm.setType(type);
            vm.setController(didWeb);

            List<X509Certificate> certificateList = null;
            try {
                certificateList = convertToCertficates(certificateItem.getCertificate());
            }catch (CertificateException e) {
                logger.error(e.getMessage(), e);
            }

            assert certificateList != null;
            X509Certificate certificate = certificateList.stream().findFirst().orElse(null);

            assert certificate != null;

            RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
            String e = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());
            String n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());

            PublicJwk publicKeyJwk = new PublicJwk();
            publicKeyJwk.setKty("RSA");
            publicKeyJwk.setN(n);
            publicKeyJwk.setE(e);
            publicKeyJwk.setAlg("RS256");
            publicKeyJwk.setX5u("https://" + baseDomain + "/.well-known/" + certificateItem.getDid() + ".pem");

            vm.setPublicKeyJwk(publicKeyJwk);

            didDocument.getVerificationMethod().add(vm);
            didDocument.getAssertionMethod().add(certificateItem.getDid());
        }

        ObjectMapper objectMapper = new ObjectMapper();
        // Convert the DID object to JSON string
        String didDocumentString = null;
        try {
            didDocumentString = objectMapper.writeValueAsString(didDocument);
        } catch (JsonProcessingException e) {
            logger.error(e.getMessage(), e);
        }
        return didDocumentString;
    }

    private List<X509Certificate> convertToCertficates(String certs) throws CertificateException {

        ByteArrayInputStream certStream = new ByteArrayInputStream(certs.getBytes(StandardCharsets.UTF_8));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (List<X509Certificate>) certFactory.generateCertificates(certStream);
    }
}
