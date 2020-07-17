/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gradle.api.internal.provider;

import org.gradle.api.Project;
import org.gradle.api.credentials.AwsCredentials;
import org.gradle.api.credentials.Credentials;
import org.gradle.api.credentials.PasswordCredentials;
import org.gradle.api.internal.tasks.NodeExecutionContext;
import org.gradle.api.internal.tasks.WorkNodeAction;
import org.gradle.api.provider.Provider;
import org.gradle.api.provider.ProviderFactory;
import org.gradle.internal.Cast;
import org.gradle.internal.credentials.DefaultPasswordCredentials;
import org.gradle.internal.logging.text.TreeFormatter;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nullable;

public class CredentialsProviderFactory {
    private final ProviderFactory providerFactory;

    public CredentialsProviderFactory(ProviderFactory providerFactory) {
        this.providerFactory = providerFactory;
    }

    public <T extends Credentials> Provider<T> provide(Class<T> credentialsType, String identity) {
        return provide(credentialsType, providerFactory.provider(() -> identity));
    }

    public <T extends Credentials> Provider<T> provide(Class<T> credentialsType, Provider<String> identity) {
        if (PasswordCredentials.class.isAssignableFrom(credentialsType)) {
            return new PasswordCredentialsProvider<>(credentialsType, identity);

        } else if (AwsCredentials.class.isAssignableFrom(credentialsType)) {
            return null;
        }
        throw new IllegalArgumentException(String.format("Unsupported credentials type: %s", credentialsType));
    }

    private static void validateIdentity(@Nullable String identity) {
        if (identity == null || identity.isEmpty() || !identity.chars().allMatch(Character::isLetterOrDigit)) {
            throw new IllegalArgumentException("Identity may contain only letters and digits, received: " + identity);
        }
    }

    private class PasswordCredentialsProvider<T extends Credentials> extends AbstractMinimalProvider<T> {
        private final Class<T> credentialsType;
        private final Provider<String> identity;
        private final Provider<String> usernamePropertyName;
        private final Provider<String> passwordPropertyName;
        private final ProviderInternal<String> usernameProperty;
        private final ProviderInternal<String> passwordProperty;

        private PasswordCredentialsProvider(Class<T> credentialsType, Provider<String> identity) {
            this.credentialsType = credentialsType;
            this.identity = identity;
            this.usernamePropertyName = identity.map(name -> name + "Username");
            this.passwordPropertyName = identity.map(name -> name + "Password");
            this.usernameProperty = Providers.internal(providerFactory.gradleProperty(usernamePropertyName));
            this.passwordProperty = Providers.internal(providerFactory.gradleProperty(passwordPropertyName));
        }

        @Override
        public ExecutionTimeValue<? extends T> calculateExecutionTimeValue() {
            return isChangingValue(usernameProperty) || isChangingValue(passwordProperty)
                    ? ExecutionTimeValue.changingValue(this)
                    : super.calculateExecutionTimeValue();
        }

        private boolean isChangingValue(ProviderInternal<?> provider) {
            return provider.calculateExecutionTimeValue().isChangingValue();
        }

        @Override
        protected Value<? extends T> calculateOwnValue(ValueConsumer consumer) {
            String name = identity.get();
            validateIdentity(name);

            Value<? extends String> usernameValue = usernameProperty.calculateValue(consumer);
            Value<? extends String> passwordValue = passwordProperty.calculateValue(consumer);

            if (usernameValue.isMissing() || passwordValue.isMissing()) {
                TreeFormatter errorBuilder = new TreeFormatter();
                errorBuilder.node("The following Gradle properties are missing for '").append(name).append("' credentials");
                errorBuilder.startChildren();
                if (usernameValue.isMissing()) {
                    errorBuilder.node(usernamePropertyName.get());
                }
                if (passwordValue.isMissing()) {
                    errorBuilder.node(passwordPropertyName.get());
                }
                errorBuilder.endChildren();
                throw new MissingValueException(errorBuilder.toString());
            }

            return Value.of(Cast.uncheckedCast(new DefaultPasswordCredentials(usernameValue.get(), passwordValue.get())));
        }

        @Nullable
        @Override
        public Class<T> getType() {
            return credentialsType;
        }

        @Override
        public ValueProducer getProducer() {
            return new PlusProducer(usernameProperty.getProducer(), passwordProperty.getProducer()).plus(getResolvingAction());
        }

        @NotNull
        private ValueProducer getResolvingAction() {
            return ValueProducer.nodeAction(new ResolveCredentialsWorkNodeAction(this));
        }
    }

    public static class ResolveCredentialsWorkNodeAction implements WorkNodeAction {
        private final Provider<? extends Credentials> provider;

        public ResolveCredentialsWorkNodeAction(Provider<? extends Credentials> provider) {
            this.provider = provider;
        }

        @Nullable
        @Override
        public Project getProject() {
            return null;
        }

        @Override
        public void run(NodeExecutionContext context) {
            // Resolve the provider
            provider.get();
        }
    }
//
//    private class AwsCredentialsProvider extends CredentialsProvider<AwsCredentials> {
//
//        AwsCredentialsProvider(String identity) {
//            super(identity);
//        }
//
//        @Override
//        public AwsCredentials call() {
//            String accessKey = getRequiredProperty("AccessKey");
//            String secretKey = getRequiredProperty("SecretKey");
//            assertRequiredValuesPresent();
//
//            AwsCredentials credentials = new DefaultAwsCredentials();
//            credentials.setAccessKey(accessKey);
//            credentials.setSecretKey(secretKey);
//            credentials.setSessionToken(getOptionalProperty("SessionToken"));
//            return credentials;
//        }
//    }

}
