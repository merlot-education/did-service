package eu.merloteducation.didservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.merloteducation.didservice.models.did.DidDocument;
import eu.merloteducation.didservice.models.did.PublicJwk;
import eu.merloteducation.didservice.models.did.VerificationMethod;
import eu.merloteducation.didservice.models.entities.ParticipantCertificate;
import eu.merloteducation.didservice.models.exceptions.*;
import eu.merloteducation.didservice.repositories.ParticipantCertificateRepository;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
import io.netty.util.internal.StringUtil;
import jakarta.transaction.Transactional;
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

import java.io.*;
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
    private static final String VM_TYPE_ID_MERLOT = "#MERLOTJWK2020";
    private static final String VM_TYPE = "JsonWebKey2020";
    private static final String VM_CONTEXT = "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/";

    private final Logger logger = LoggerFactory.getLogger(DidService.class);

    private final ParticipantCertificateRepository certificateRepository;

    private final ObjectMapper objectMapper;

    private final String didDomain;

    private final String certificateIssuer;

    private final String defaultCertPath;

    private final boolean merlotVMEnabled;

    public DidServiceImpl(@Value("${merlot-cert-path:#{null}}") String defaultCertPath,
                          @Value("${merlot-verification-method-enabled}") boolean merlotVMEnabled,
                          @Value("${certificate-issuer}") String certificateIssuer,
                          @Value("${did-domain}") String didDomain,
                          @Autowired ObjectMapper objectMapper,
                          @Autowired  ParticipantCertificateRepository certificateRepository
        ) {

        this.defaultCertPath = defaultCertPath;
        this.merlotVMEnabled = merlotVMEnabled;
        this.certificateIssuer = certificateIssuer;
        this.didDomain = didDomain;
        this.objectMapper = objectMapper;
        this.certificateRepository = certificateRepository;
    }

    @Override
    @Transactional
    public String getCertificate(String id) throws ParticipantNotFoundException {

        String didWeb = getDidWebForParticipant(id);

        ParticipantCertificate participantCertificate = certificateRepository.findByDid(didWeb);

        if (participantCertificate == null) {
            throw new ParticipantNotFoundException("Participant could not be found.");
        }

        return participantCertificate.getCertificate();
    }

    @Override
    @Transactional
    public String getDidDocument(String id) throws ParticipantNotFoundException, DidDocumentGenerationException {

        String didWeb = getDidWebForParticipant(id);

        ParticipantCertificate participantCertificate = certificateRepository.findByDid(didWeb);

        if (participantCertificate == null) {
            throw new ParticipantNotFoundException("Participant could not be found.");
        }

        String didDocumentString = null;

        try {
            didDocumentString = createDidDocument(participantCertificate);
        } catch (Exception e) {
            throw new DidDocumentGenerationException(e.getMessage());
        }

        return didDocumentString;
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
        throws CryptographicAssetGenerationException, PemConversionException, RequestArgumentException {

        X509Certificate cert = null;
        KeyPair keyPair = null;

        String certificateSubject = request.getSubject();

        if (certificateSubject == null || certificateSubject.isBlank()) {
            throw new RequestArgumentException("Missing or empty subject name.");
        }

        String didWeb = generateDidWeb(certificateSubject);

        // The list of Relative Distinguished Names (RDN) forms the Distinguished Name (DN) of an issuer or a subject.
        // Common Name (CN) is currently the only RDN used here. Organization (O) and Country (C) could be added to the minimal list of RDNs.
        X500Name issuerName = new X500Name("CN=" + certificateIssuer);
        X500Name subjectName = new X500Name("CN=" + certificateSubject);

        try {
            keyPair = createKeyPair();
        } catch (Exception e) {
            throw new CryptographicAssetGenerationException("Key pair generation failed: " + e.getMessage());
        }

        try {
            cert = createCertificate(issuerName, subjectName, keyPair);
        } catch (Exception e) {
            throw new CryptographicAssetGenerationException("Certificate generation failed: " + e.getMessage());
        }

        storeDidAndCertificate(didWeb, cert);
        return createParticipantDidPrivateKeyDto(didWeb, keyPair.getPrivate());
    }

    private String generateDidWeb(String seed) {

        String uuid = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
        return getDidWebForParticipant(uuid);
    }

    private String getDidWebForParticipant(String id) {

        return getDidWebForMerlot() + ":participant:" + id;
    }

    private String getDidWebForMerlot() {

        return "did:web:" + didDomain.replaceFirst(":", "%3A");
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

        contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, certSerialNumber,
            startDate, endDate, subjectName, keyPair.getPublic());

        // Extensions --------------------------
        // Basic Constraints mark the certificate as a Certificate Authority (CA) certificate or an End Entity certificate.
        // A CA is allowed to sign other certificates.
        // An End Entity is e.g., a user or a server.
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true,
            basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        cert = new JcaX509CertificateConverter().setProvider(Security.getProvider("BC"))
            .getCertificate(certBuilder.build(contentSigner));

        return cert;
    }

    @Transactional
    private void storeDidAndCertificate(String did, X509Certificate certificate) throws PemConversionException {

        ParticipantCertificate cert = new ParticipantCertificate();
        cert.setDid(did);
        cert.setCertificate(convertCertificateToPemString(certificate));

        certificateRepository.save(cert);
    }

    private String convertCertificateToPemString(X509Certificate certificate) throws PemConversionException {

        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        try {
            pemWriter.writeObject(certificate);
            pemWriter.close();
        } catch (IOException e) {
            throw new PemConversionException("Certificate conversion failed: " + e.getMessage());
        }
        return sw.toString();
    }

    private String convertPrivateKeyToPemString(PrivateKey privateKey) throws PemConversionException {

        StringWriter sw = new StringWriter();
        PemWriter pemWriter = new PemWriter(sw);
        try {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.close();
        } catch (IOException e) {
            throw new PemConversionException("Private key conversion failed: " + e.getMessage());
        }
        return sw.toString();
    }

    private ParticipantDidPrivateKeyDto createParticipantDidPrivateKeyDto(String did, PrivateKey privateKey)
        throws PemConversionException {

        ParticipantDidPrivateKeyDto dto = new ParticipantDidPrivateKeyDto();
        dto.setDid(did);
        dto.setVerificationMethod(did + VM_TYPE_ID);
        dto.setPrivateKey(convertPrivateKeyToPemString(privateKey));

        if (merlotVMEnabled) {
            dto.setMerlotVerificationMethod(did + VM_TYPE_ID_MERLOT);
        }

        return dto;
    }

    private String createDidDocument(ParticipantCertificate participantCertificate)
        throws JsonProcessingException, PemConversionException, CertificateException {

        String didWebParticipant = participantCertificate.getDid();

        DidDocument didDocument = new DidDocument();
        didDocument.setContext(List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"));
        didDocument.setId(didWebParticipant);
        didDocument.setVerificationMethod(new ArrayList<>());

        VerificationMethod participantVerificationMethod = getVerificationMethod(didWebParticipant, participantCertificate.getCertificate());
        didDocument.getVerificationMethod().add(participantVerificationMethod);

        if (merlotVMEnabled) {
            VerificationMethod merlotVerificationMethod = getVerificationMethod(getDidWebForMerlot(), getMerlotCertificatePemString());
            merlotVerificationMethod.setId(didWebParticipant + VM_TYPE_ID_MERLOT);
            didDocument.getVerificationMethod().add(merlotVerificationMethod);
        }

        // Return JSON string converted the DID object
        return objectMapper.writeValueAsString(didDocument);
    }

    private VerificationMethod getVerificationMethod(String didWeb, String certificate) throws PemConversionException {
        VerificationMethod vm = new VerificationMethod();
        vm.setContext(List.of(VM_CONTEXT));
        vm.setId(didWeb + VM_TYPE_ID);
        vm.setType(VM_TYPE);
        vm.setController(didWeb);

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = convertPemStringToCertificate(certificate);
        } catch (CertificateException e) {
            throw new PemConversionException("Certificate conversion failed: " + e.getMessage());
        }

        RSAPublicKey rsaPublicKey = (RSAPublicKey) x509Certificate.getPublicKey();
        String e = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());
        String n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());

        PublicJwk publicKeyJwk = new PublicJwk();
        publicKeyJwk.setKty("RSA");
        publicKeyJwk.setN(n);
        publicKeyJwk.setE(e);
        publicKeyJwk.setAlg("PS256");

        String didWebBase = didWeb.replace("did:web:", "") // remove did type prefix
            .replaceFirst("#.*", ""); // remove verification method reference
        String certificateUrl = getDidDocumentUri(didWebBase).replace("did.json", "cert.pem");

        publicKeyJwk.setX5u(certificateUrl);

        vm.setPublicKeyJwk(publicKeyJwk);

        return vm;
    }

    /**
     * Given the domain part of the did:web, return the resulting URI. See <a
     * href="https://w3c-ccg.github.io/did-method-web/#read-resolve">did-web specification</a> for reference.
     *
     * @param didWeb did:web without prefix and key reference
     * @return did web URI
     */
    private static String getDidDocumentUri(String didWeb) {

        boolean containsSubpath = didWeb.contains(":");
        StringBuilder didDocumentUriBuilder = new StringBuilder();
        didDocumentUriBuilder.append(
            didWeb.replace(":", "/") // Replace ":" with "/" in the method specific identifier to
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

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        certificateList = (List<X509Certificate>) certFactory.generateCertificates(certStream);

        return certificateList.stream().findFirst().orElse(null);
    }

    /**
     * Load the merlot certificate from file.
     *
     * @return string representation of certificate
     * @throws CertificateException error during loading of the certificate
     */
    private String getMerlotCertificatePemString() throws CertificateException {
        try (InputStream certificateStream = StringUtil.isNullOrEmpty(defaultCertPath) ?
            DidServiceImpl.class.getClassLoader().getResourceAsStream("cert.ss.pem")
            : new FileInputStream(defaultCertPath)) {
            return new String(Objects.requireNonNull(certificateStream,
                "Certificate input stream is null.").readAllBytes(),
                StandardCharsets.UTF_8);
        } catch (IOException | NullPointerException e) {
            throw new CertificateException("Failed to read merlot certificate. " + e.getMessage());
        }
    }
}
