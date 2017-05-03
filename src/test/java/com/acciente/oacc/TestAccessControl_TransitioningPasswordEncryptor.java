/*
 * Copyright 2009-2017, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc;

import com.acciente.oacc.encryptor.TransitioningPasswordEncryptor;
import com.acciente.oacc.encryptor.bcrypt.BCryptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.LegacyJasyptPasswordEncryptor;
import com.acciente.oacc.helper.SQLAccessControlSystemResetUtil;
import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import org.junit.Before;
import org.junit.Test;

import static com.acciente.oacc.TestAccessControlBase.generateUniqueDomainName;
import static com.acciente.oacc.TestAccessControlBase.generateUniqueExternalId;
import static com.acciente.oacc.TestAccessControlBase.generateUniqueResourceClassName;

public class TestAccessControl_TransitioningPasswordEncryptor {
   private static final Resource SYS_RESOURCE = Resources.getInstance(0);

   private AccessControlContext systemContextWithLegacyEncryptor;
   private AccessControlContext systemContextWithTransitioningEncryptor;

   private AccessControlContext userContextWithLegacyEncryptor;
   private AccessControlContext userContextWithTransitioningEncryptor;
   private AccessControlContext userContextWithBcryptEncryptor;

   private String               resourceExternalId;
   private String               resourceClassName;
   private String               resourceDomainName;
   private PasswordCredentials  resourceCredentials;

   @Before
   public void setUpTest() throws Exception {
      // use the legacy built-in password encryptor code (from OACC v2.00 rc7 and before) as the "old" encryptor
      final LegacyJasyptPasswordEncryptor legacyJasyptPasswordEncryptor =
            LegacyJasyptPasswordEncryptor.newInstance();

      SQLAccessControlSystemResetUtil.resetOACC(TestConfigLoader.getDataSource(),
                                                TestConfigLoader.getDatabaseSchema(),
                                                TestConfigLoader.getOaccRootPassword(),
                                                legacyJasyptPasswordEncryptor);

      systemContextWithLegacyEncryptor
            = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     TestConfigLoader.getSQLProfile(),
                                                                     legacyJasyptPasswordEncryptor);
      systemContextWithLegacyEncryptor.authenticate(SYS_RESOURCE,
                                                    PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

      userContextWithLegacyEncryptor
            = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     TestConfigLoader.getSQLProfile(),
                                                                     legacyJasyptPasswordEncryptor);

      // uses the transitioning password encryptor with BCrypt as the "new" password encryptor and
      // the legacy built-in password encryptor code (from OACC v2.00 rc7 and before) as the "old" encryptor
      final BCryptPasswordEncryptor bCryptPasswordEncryptor = BCryptPasswordEncryptor.newInstance(6);
      final TransitioningPasswordEncryptor transitioningPasswordEncryptor =
            TransitioningPasswordEncryptor.newInstance(
                  bCryptPasswordEncryptor,
                  LegacyJasyptPasswordEncryptor.newInstance());

      systemContextWithTransitioningEncryptor
            = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     TestConfigLoader.getSQLProfile(),
                                                                     transitioningPasswordEncryptor);
      systemContextWithTransitioningEncryptor.authenticate(SYS_RESOURCE,
                                                           PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

      userContextWithTransitioningEncryptor
            = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     TestConfigLoader.getSQLProfile(),
                                                                     transitioningPasswordEncryptor);

      userContextWithBcryptEncryptor
            = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     TestConfigLoader.getSQLProfile(),
                                                                     bCryptPasswordEncryptor);

      resourceExternalId = generateUniqueExternalId();
      resourceClassName = generateAuthenticatableResourceClass();
      resourceDomainName = generateDomain();
      resourceCredentials = PasswordCredentials.newInstance(generateRandomPassword().toCharArray());
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingLegacyEncryptor() throws Exception {
      final Resource resource = systemContextWithLegacyEncryptor.createResource(resourceClassName,
                                                                                resourceDomainName,
                                                                                resourceExternalId,
                                                                                resourceCredentials);

      userContextWithLegacyEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingTransitioningEncryptor() throws Exception {
      final Resource resource = systemContextWithLegacyEncryptor.createResource(resourceClassName,
                                                                                resourceDomainName,
                                                                                resourceExternalId,
                                                                                resourceCredentials);

      userContextWithTransitioningEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithTransitioningPasswordUsingTransitioningEncryptor() throws Exception {
      final Resource resource = systemContextWithTransitioningEncryptor.createResource(resourceClassName,
                                                                                       resourceDomainName,
                                                                                       resourceExternalId,
                                                                                       resourceCredentials);

      userContextWithTransitioningEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithTransitioningPasswordUsingBcryptEncryptor() throws Exception {
      final Resource resource = systemContextWithTransitioningEncryptor.createResource(resourceClassName,
                                                                                       resourceDomainName,
                                                                                       resourceExternalId,
                                                                                       resourceCredentials);

      userContextWithBcryptEncryptor.authenticate(resource, resourceCredentials);
   }

   private String generateAuthenticatableResourceClass() {
      final String resourceClassName = generateUniqueResourceClassName();
      systemContextWithLegacyEncryptor.createResourceClass(resourceClassName, true, false);
      return resourceClassName;
   }

   private String generateDomain() {
      final String domainName = generateUniqueDomainName();
      systemContextWithLegacyEncryptor.createDomain(domainName);
      return domainName;
   }

   private static String generateRandomPassword() {
      return "pwd_" + Math.random();
   }
}
