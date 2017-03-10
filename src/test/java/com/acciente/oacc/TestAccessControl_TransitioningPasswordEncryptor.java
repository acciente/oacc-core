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

   private AccessControlContext systemAccessControlContextWithLegacyEncryptor;
   private AccessControlContext systemAccessControlContextWithTransitioningEncryptor;

   private AccessControlContext accessControlContextWithLegacyEncryptor;
   private AccessControlContext accessControlContextWithTransitioningEncryptor;
   private String               resourceExternalId;
   private String               resourceClassName;
   private String               resourceDomainName;
   private PasswordCredentials  resourceCredentials;

   @Before
   public void setUpTest() throws Exception {
      {
         // use the legacy built-in password encryptor code (from OACC v2.00 rc7 and before) as the "old" encryptor
         final LegacyJasyptPasswordEncryptor legacyJasyptPasswordEncryptor =
               LegacyJasyptPasswordEncryptor.getPasswordEncryptor();

         SQLAccessControlSystemResetUtil.resetOACC(TestConfigLoader.getDataSource(),
                                                   TestConfigLoader.getDatabaseSchema(),
                                                   TestConfigLoader.getOaccRootPassword(),
                                                   legacyJasyptPasswordEncryptor);

         systemAccessControlContextWithLegacyEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        legacyJasyptPasswordEncryptor);
         systemAccessControlContextWithLegacyEncryptor.authenticate(SYS_RESOURCE,
                                                                    PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

         accessControlContextWithLegacyEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        legacyJasyptPasswordEncryptor);
      }

      {
         // uses the transitioning password encryptor with BCrypt as the "new" password encryptor and
         // the legacy built-in password encryptor code (from OACC v2.00 rc7 and before) as the "old" encryptor
         final TransitioningPasswordEncryptor transitioningPasswordEncryptor = TransitioningPasswordEncryptor.getPasswordEncryptor(
               BCryptPasswordEncryptor.newInstance(6),
               LegacyJasyptPasswordEncryptor.getPasswordEncryptor());

         systemAccessControlContextWithTransitioningEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        transitioningPasswordEncryptor);
         systemAccessControlContextWithTransitioningEncryptor.authenticate(SYS_RESOURCE,
                                                                           PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

         accessControlContextWithTransitioningEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        transitioningPasswordEncryptor);
      }

      resourceExternalId = generateUniqueExternalId();
      resourceClassName = generateResourceClass(true, false);
      resourceDomainName = generateDomain();
      resourceCredentials = PasswordCredentials.newInstance(generateRandomPassword().toCharArray());
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingLegacyEncryptor() throws Exception {
      final Resource resource = systemAccessControlContextWithLegacyEncryptor.createResource(resourceClassName,
                                                                                             resourceDomainName,
                                                                                             resourceExternalId,
                                                                                             resourceCredentials);

      accessControlContextWithLegacyEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingTransitioningEncryptor() throws Exception {
      final Resource resource = systemAccessControlContextWithLegacyEncryptor.createResource(resourceClassName,
                                                                                             resourceDomainName,
                                                                                             resourceExternalId,
                                                                                             resourceCredentials);

      accessControlContextWithTransitioningEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithTransitioningPasswordUsingTransitioningEncryptor() throws Exception {
      final Resource resource = systemAccessControlContextWithTransitioningEncryptor.createResource(resourceClassName,
                                                                                                    resourceDomainName,
                                                                                                    resourceExternalId,
                                                                                                    resourceCredentials);

      accessControlContextWithTransitioningEncryptor.authenticate(resource, resourceCredentials);
   }

   private String generateResourceClass(boolean authenticatable,
                                        boolean nonAuthenticatedCreateAllowed) {
      final String resourceClassName = generateUniqueResourceClassName();
      systemAccessControlContextWithLegacyEncryptor.createResourceClass(resourceClassName,
                                                                        authenticatable,
                                                                        nonAuthenticatedCreateAllowed);
      return resourceClassName;
   }

   private String generateDomain() {
      final String domainName = generateUniqueDomainName();
      systemAccessControlContextWithLegacyEncryptor.createDomain(domainName);
      return domainName;
   }

   private static String generateRandomPassword() {
      return "pwd_" + Math.random();
   }
}
