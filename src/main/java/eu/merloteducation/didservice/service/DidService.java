package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.didservice.models.dtos.ParticipantDidPrivateKeyDto;

public interface DidService {
    /**
     * Returns a certificate by id.
     *
     * @param certId id to retrieve the certificate with
     * @return the certificate
     */
    public String getCertificate(String certId);

    /**
     * Returns the DID document containing all MERLOT-generated did:webs and associated certificates.
     *
     * @return the did document as string
     */
    public String getDidDocument();

    /**
     * Generates a did:web, a key pair and certificate. Returns the did:web and private key.
     *
     * @param request with information needed for certificate generation
     * @return dto containing the generated did:web and private key
     */
    public ParticipantDidPrivateKeyDto generateDidAndPrivateKey(ParticipantDidPrivateKeyCreateRequest request);
}
