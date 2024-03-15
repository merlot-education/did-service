package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;

public interface DidService {
    /**
     * Returns a certificate for a given id.
     *
     * @param id id to retrieve the certificate with
     * @return the certificate
     */
    public String getCertificate(String id) throws Exception;

    /**
     * Returns the DID document for a given id.
     *
     * @param id id to retrieve the DID document with
     * @return the did document as string
     */
    public String getDidDocument(String id) throws Exception;

    /**
     * Generates a did:web, a key pair and certificate. Returns the did:web and private key.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web and private key
     */
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(ParticipantDidPrivateKeyCreateRequest request)
        throws Exception;
}
