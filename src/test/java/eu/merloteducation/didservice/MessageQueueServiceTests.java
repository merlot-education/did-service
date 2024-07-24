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

package eu.merloteducation.didservice;

import eu.merloteducation.didservice.models.exceptions.CryptographicAssetGenerationException;
import eu.merloteducation.didservice.models.exceptions.PemConversionException;
import eu.merloteducation.didservice.models.exceptions.RequestArgumentException;
import eu.merloteducation.didservice.service.DidService;
import eu.merloteducation.didservice.service.MessageQueueService;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyCreateRequest;
import eu.merloteducation.modelslib.api.did.ParticipantDidPrivateKeyDto;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@SpringBootTest
@ExtendWith(MockitoExtension.class)
@EnableConfigurationProperties
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MessageQueueServiceTests {
    @Autowired
    MessageQueueService messageQueueService;

    @Mock
    DidService didService;

    @BeforeAll
    void beforeAll() throws Exception {

        ReflectionTestUtils.setField(messageQueueService, "didService", didService);

        when(didService.generateDidAndPrivateKey(new ParticipantDidPrivateKeyCreateRequest())).thenThrow(
            RequestArgumentException.class);
        when(didService.generateDidAndPrivateKey(new ParticipantDidPrivateKeyCreateRequest("broken pem"))).thenThrow(
            PemConversionException.class);
        when(
            didService.generateDidAndPrivateKey(new ParticipantDidPrivateKeyCreateRequest("broken key gen"))).thenThrow(
            CryptographicAssetGenerationException.class);

        doReturn(new ParticipantDidPrivateKeyDto()).when(didService)
            .generateDidAndPrivateKey(new ParticipantDidPrivateKeyCreateRequest("valid"));
    }

    @Test
    void requestDidPrivateKey() {

        ParticipantDidPrivateKeyDto dto = messageQueueService.didPrivateKeyRequestedListener(
            new ParticipantDidPrivateKeyCreateRequest("valid"));
        assertNotNull(dto);
    }

    @Test
    void requestDidPrivateKeyBrokenPem() {

        ParticipantDidPrivateKeyDto dto = messageQueueService.didPrivateKeyRequestedListener(
            new ParticipantDidPrivateKeyCreateRequest("broken pem"));
        assertNull(dto);
    }

    @Test
    void requestDidPrivateKeyBrokenKeyGen() {

        ParticipantDidPrivateKeyDto dto = messageQueueService.didPrivateKeyRequestedListener(
            new ParticipantDidPrivateKeyCreateRequest("broken key gen"));
        assertNull(dto);
    }

    @Test
    void requestDidPrivateKeyInvalidRequest() {

        ParticipantDidPrivateKeyDto dto = messageQueueService.didPrivateKeyRequestedListener(
            new ParticipantDidPrivateKeyCreateRequest());
        assertNull(dto);
    }
}
