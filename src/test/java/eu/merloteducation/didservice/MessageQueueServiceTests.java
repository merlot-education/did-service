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
public class MessageQueueServiceTests {
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
