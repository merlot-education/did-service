package eu.merloteducation.didservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.merloteducation.didservice.models.did.DidDocument;
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
import java.io.IOException;
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

    private static final String VM_TYPE_ID = "#JWK2020";

    private final Logger logger = LoggerFactory.getLogger(DidService.class);

    @Autowired
    private ParticipantCertificateRepository certificateRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${did-domain}")
    private String didDomain;

    @Value("${certificate-issuer}")
    private String certificateIssuer;

    @Override
    public String getCertificate(String id) throws Exception {

        String didWeb = getDidWeb(id);

        ParticipantCertificate participantCertificate = certificateRepository.findByDid(didWeb);

        if (participantCertificate == null) {
            throw new Exception("Participant could not be found.");
        }

        return participantCertificate.getCertificate();
    }

    @Override
    public String getDidDocument(String id) throws Exception {

        String didWeb = getDidWeb(id);

        ParticipantCertificate participantCertificate = certificateRepository.findByDid(didWeb);

        if (participantCertificate == null) {
            throw new Exception("Participant could not be found.");
        }

        return createDidDocument(participantCertificate);
    }

    /**
     * Generates a did:web, a key pair and a corresponding certificate. Returns the did:web, the verification method as
     * well as the associated private key and stores the certificate.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web, the verification method and the associated private key
     */
    @Override
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(ParticipantDidPrivateKeyCreateRequest request)
        throws Exception {

        X509Certificate cert = null;
        KeyPair keyPair = null;

        String didWeb = generateDidWeb(request.getSubject());

        // The list of Relative Distinguished Names (RDN) forms the Distinguished Name (DN) of an issuer or a subject.
        // Common Name (CN) is currently the only RDN used here. Organization (O) and Country (C) could be added to the minimal list of RDNs.
        X500Name issuerName = new X500Name("CN=" + certificateIssuer);
        X500Name subjectName = new X500Name("CN=" + request.getSubject());

        keyPair = createKeyPair();
        cert = createCertificate(issuerName, subjectName, keyPair);
        storeDidAndCertificate(didWeb, cert);
        return createParticipantDidPrivateKeyDto(didWeb, keyPair.getPrivate());
    }

    private String generateDidWeb(String seed) {

        String uuid = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
        return getDidWeb(uuid);
    }

    private String getDidWeb(String id) {

        return "did:web:" + didDomain + ":participant:" + id;
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate createCertificate(X500Name issuerName, X500Name subjectName, KeyPair keyPair)
        throws OperatorCreationException, CertIOException, CertificateException {

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
            throw e;
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
            throw e;
        }
        // -------------------------------------

        try {
            cert = new JcaX509CertificateConverter().setProvider(Security.getProvider("BC"))
                .getCertificate(certBuilder.build(contentSigner));
        } catch (CertificateException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return cert;
    }

    private void storeDidAndCertificate(String did, X509Certificate certificate) throws IOException {

        ParticipantCertificate cert = new ParticipantCertificate();
        cert.setDid(did);
        cert.setCertificate(convertCertificateToPemString(certificate));

        certificateRepository.save(cert);
    }

    private String convertCertificateToPemString(X509Certificate certificate) throws IOException {

        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
            pemWriter.writeObject(certificate);
            pemWriter.close();
            return sw.toString();
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    private String convertPrivateKeyToPemString(PrivateKey privateKey) throws IOException {

        try {
            StringWriter sw = new StringWriter();
            PemWriter pemWriter = new PemWriter(sw);
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.close();
            return sw.toString();
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
    }

    private ParticipantDidPrivateKeyDto createParticipantDidPrivateKeyDto(String did, PrivateKey privateKey)
        throws IOException {

        ParticipantDidPrivateKeyDto dto = new ParticipantDidPrivateKeyDto();
        dto.setDid(did);
        dto.setVerificationMethod(did + VM_TYPE_ID);
        dto.setPrivateKey(convertPrivateKeyToPemString(privateKey));

        return dto;
    }

    private String createDidDocument(ParticipantCertificate participantCertificate)
        throws CertificateException, JsonProcessingException {

        String didWeb = participantCertificate.getDid();

        DidDocument didDocument = new DidDocument();
        didDocument.setContext(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"));
        didDocument.setId(didWeb);
        didDocument.setVerificationMethod(new ArrayList<>());

        String vmContext = "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/";
        String type = "JsonWebKey2020";

        VerificationMethod vm = new VerificationMethod();
        vm.setContext(List.of(vmContext));
        vm.setId(didWeb + VM_TYPE_ID);
        vm.setType(type);
        vm.setController(didWeb);

        X509Certificate x509Certificate = convertPemStringToCertificate(participantCertificate.getCertificate());

        RSAPublicKey rsaPublicKey = (RSAPublicKey) x509Certificate.getPublicKey();
        String e = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());
        String n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());

        PublicJwk publicKeyJwk = new PublicJwk();
        publicKeyJwk.setKty("RSA");
        publicKeyJwk.setN(n);
        publicKeyJwk.setE(e);
        publicKeyJwk.setAlg("PS256");

        String didWebBase = didWeb
                .replace("did:web:", "") // remove did type prefix
                .replaceFirst("#.*", ""); // remove verification method reference
        String certificateUrl = getDidDocumentUri(didWebBase)
                .replace("did.json", "cert.pem");

        publicKeyJwk.setX5u(certificateUrl);

        vm.setPublicKeyJwk(publicKeyJwk);

        didDocument.getVerificationMethod().add(vm);

        // Convert the DID object to JSON string
        String didDocumentString;
        try {
            didDocumentString = objectMapper.writeValueAsString(didDocument);
        } catch (JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            throw ex;
        }

        return didDocumentString;
    }

    /**
     * Given the domain part of the did:web, return the resulting URI.
     * See <a href="https://w3c-ccg.github.io/did-method-web/#read-resolve">did-web specification</a> for reference.
     *
     * @param didWeb did:web without prefix and key reference
     * @return did web URI
     */
    private static String getDidDocumentUri(String didWeb) {
        boolean containsSubpath = didWeb.contains(":");
        StringBuilder didDocumentUriBuilder = new StringBuilder();
        didDocumentUriBuilder.append(didWeb
                .replace(":", "/") // Replace ":" with "/" in the method specific identifier to
                // obtain the fully qualified domain name and optional path.
                .replace("%3A", ":")); // If the domain contains a port percent decode the colon.

        // Generate an HTTPS URL to the expected location of the DID document by prepending https://.
        didDocumentUriBuilder.insert(0, "https://");
        if (!containsSubpath) {
            // If no path has been specified in the URL, append /.well-known.
            didDocumentUriBuilder.append("/.well-known");
        }
        // Append /did.json to complete the URL.
        didDocumentUriBuilder.append("/did.json");

        return didDocumentUriBuilder.toString();
    }

    @SuppressWarnings("unchecked")
    private X509Certificate convertPemStringToCertificate(String certs) throws CertificateException {

        ByteArrayInputStream certStream = new ByteArrayInputStream(certs.getBytes(StandardCharsets.UTF_8));

        List<X509Certificate> certificateList = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certificateList = (List<X509Certificate>) certFactory.generateCertificates(certStream);
        } catch (CertificateException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return certificateList.stream().findFirst().orElse(null);
    }
}
