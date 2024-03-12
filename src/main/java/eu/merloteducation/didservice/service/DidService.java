package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

@Service
public class DidService {
    private static final String CERTIFICATE_ALIAS = "YOUR_CERTIFICATE_NAME";

    private static final String CERTIFICATE_ALGORITHM = "RSA";

    private static final String CERTIFICATE_DN = "CN=cn, O=o, L=L, ST=il, C= c";

    private static final String CERTIFICATE_NAME = "keystore.test";

    private static final int CERTIFICATE_BITS = 4096;

    private final Logger logger = LoggerFactory.getLogger(DidService.class);

    /**
     * @param participantDid did:web of the participant
     * @return the certificate of the participant
     */
    public String getCertificate(String participantDid) {

        return "certificate for " + participantDid;
    }

    /**
     * @return the did document as string
     */
    public String getDidDocument() {

        return "DID document";
    }

    /**
     * @param seed to use for DID generation
     * @return dto containing the generated did:web and private key
     */
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(String seed) {
        // TODO replace seed with object containing issuer name and subject name (subject name could be used as seed)

        X509Certificate cert = null;
        KeyPairGenerator keyPairGenerator = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
        }

        assert keyPairGenerator != null;
        keyPairGenerator.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name issuerName = new X500Name("issuerName");
        X500Name subjectName = new X500Name("subjectName");
        BigInteger certSerialNumber = new BigInteger(
            Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 100); // <-- 100 Yr validity

        Date endDate = calendar.getTime();

        String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

        ContentSigner contentSigner = null;

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

        assert cert != null;


        storeDidAndCertificate("did", cert.toString());

        ParticipantDidPrivateKeyDto dto = new ParticipantDidPrivateKeyDto();
        dto.setPrivateKey(keyPair.getPrivate().toString());

        return dto;
    }

    private void storeDidAndCertificate(String did, String certificate) {

    }
}
