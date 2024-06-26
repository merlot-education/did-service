package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.models.exceptions.*;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;

import java.security.cert.CertificateException;

public interface DidService {
    /**
     * Returns a certificate for a given id.
     *
     * @param id id to retrieve the certificate with
     * @return the certificate
     */
    String getCertificate(String id) throws ParticipantNotFoundException;

    /**
     * Returns a certificate for the MERLOT federation.
     *
     * @return the certificate
     */
    String getMerlotCertificate() throws CertificateException;

    /**
     * Returns the DID document for a given id.
     *
     * @param id id to retrieve the DID document with
     * @return the did document as string
     */
    String getDidDocument(String id) throws ParticipantNotFoundException, DidDocumentGenerationException;

    /**
     * Returns the DID document for the MERLOT federation.
     *
     * @return the did document as string
     */
    String getMerlotDidDocument() throws DidDocumentGenerationException;

    /**
     * Generates a did:web, a key pair and certificate. Returns the did:web and private key.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web and private key
     */
    ParticipantDidPrivateKeyDto generateDidAndPrivateKey(ParticipantDidPrivateKeyCreateRequest request)
        throws CryptographicAssetGenerationException, PemConversionException, RequestArgumentException;
}
