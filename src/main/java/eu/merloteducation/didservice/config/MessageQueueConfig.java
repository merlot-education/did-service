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

package eu.merloteducation.didservice.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MessageQueueConfig {
    public static final String DID_SERVICE_EXCHANGE = "service.exchange";

    public static final String DID_PRIVATE_KEY_REQUEST_KEY = "request.did_privatekey";

    public static final String DID_PRIVATE_KEY_REQUEST_QUEUE = "did.request.did_privatekey.queue";

    @Bean
    DirectExchange didServiceExchange() {

        return new DirectExchange(DID_SERVICE_EXCHANGE);
    }

    @Bean
    Binding requestedDidPrivateKeyBinding(Queue didPrivateKeyRequestedQueue, DirectExchange didServiceExchange) {

        return BindingBuilder.bind(didPrivateKeyRequestedQueue).to(didServiceExchange)
            .with(DID_PRIVATE_KEY_REQUEST_KEY);
    }

    @Bean
    public Queue didPrivateKeyRequestedQueue() {

        return new Queue(DID_PRIVATE_KEY_REQUEST_QUEUE, false);
    }

    @Bean
    public MessageConverter converter(){
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public AmqpTemplate amqpTemplate(ConnectionFactory connectionFactory){
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(converter());
        return rabbitTemplate;
    }
}
