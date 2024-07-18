/*
 *  Copyright 2024 Dataport. All rights reserved. Developed as part of the MERLOT project.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package eu.merloteducation.didservice.service;

import eu.merloteducation.didservice.config.MessageQueueConfig;
import eu.merloteducation.didservice.models.exceptions.CryptographicAssetGenerationException;
import eu.merloteducation.didservice.models.exceptions.PemConversionException;
import eu.merloteducation.didservice.models.exceptions.RequestArgumentException;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MessageQueueService {

    @Autowired
    DidService didService;

    private final Logger logger = LoggerFactory.getLogger(MessageQueueService.class);

    /**
     * Listen for the event that a did:web and private key was requested on the message bus. Generates a did:web, a key
     * pair and a corresponding certificate. Returns the did:web, the verification method as well as the associated
     * private key and stores the certificate.
     * NOTE: currently MERLOT is no longer using the generated private/public key pair as it switched
     * to using the Federation Let's Encrypt certificate for signature. For future extensions this old key pair is
     * left in the code.
     *
     * @param request with information needed for certificate generation
     */
    @RabbitListener(queues = MessageQueueConfig.DID_PRIVATE_KEY_REQUEST_QUEUE)
    public ParticipantDidPrivateKeyDto didPrivateKeyRequestedListener(ParticipantDidPrivateKeyCreateRequest request) {

        logger.info("Did:web and private key requested for {}", request);
        try {
            return didService.generateDidAndPrivateKey(request);
        } catch (CryptographicAssetGenerationException e1) {
            logger.error("Cryptographic asset creation failed: " + e1.getMessage());
            return null;
        } catch (PemConversionException e2) {
            logger.error("PEM conversion failed: " + e2.getMessage());
            return null;
        } catch (RequestArgumentException e3) {
            logger.error("Invalid request arguments:" + e3.getMessage());
            return null;
        }
    }
}
