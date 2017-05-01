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
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.LegacyJasyptPasswordEncryptor;
import com.acciente.oacc.helper.SQLAccessControlSystemResetUtil;
import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import org.junit.Before;
import org.junit.Test;

import static com.acciente.oacc.TestAccessControlBase.generateUniqueDomainName;
import static com.acciente.oacc.TestAccessControlBase.generateUniqueExternalId;
import static com.acciente.oacc.TestAccessControlBase.generateUniqueResourceClassName;

public class TestAccessControl_JasyptEncryptorsIncludingBackwardsCompatibility {
   private static final Resource SYS_RESOURCE = Resources.getInstance(0);

   private AccessControlContext systemContextUsingLegacyEncryptor;
   private AccessControlContext userContextUsingLegacyEncryptor;

   private AccessControlContext systemContextUsingCurrentWithLegacyFallbackEncryptor;
   private AccessControlContext userContextUsingCurrentEncryptor;
   private AccessControlContext userContextUsingCurrentWithLegacyFallbackEncryptor;

   private String              resourceExternalId;
   private String              resourceClassName;
   private String              resourceDomainName;
   private PasswordCredentials resourceCredentials;

   @Before
   public void setUpTest() throws Exception {
      // uses the legacy built-in password encryptor code (from OACC v2.00 rc7 and before)
      {
         final LegacyJasyptPasswordEncryptor legacyJasyptPasswordEncryptor =
               LegacyJasyptPasswordEncryptor.newInstance();

         SQLAccessControlSystemResetUtil.resetOACC(TestConfigLoader.getDataSource(),
                                                   TestConfigLoader.getDatabaseSchema(),
                                                   TestConfigLoader.getOaccRootPassword(),
                                                   legacyJasyptPasswordEncryptor);

         systemContextUsingLegacyEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        legacyJasyptPasswordEncryptor);
         systemContextUsingLegacyEncryptor.authenticate(SYS_RESOURCE,
                                                        PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

         userContextUsingLegacyEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        legacyJasyptPasswordEncryptor);
      }

      // this uses the latest Jasypt password encryptor code
      {
         // we use values different values from the default
         final JasyptPasswordEncryptor jasyptPasswordEncryptor = JasyptPasswordEncryptor.newInstance("MD5", 2000, 32);

         // we need to use a transitioning password encryptor that falls back to a LegacyJasyptPasswordEncryptor for
         // the system context here since the OACC root password was written to using a LegacyJasyptPasswordEncryptor in
         // the call to SQLAccessControlSystemResetUtil.resetOACC(...) above
         final TransitioningPasswordEncryptor transitioningPasswordEncryptor =
               TransitioningPasswordEncryptor.newInstance(
                     jasyptPasswordEncryptor,
                     LegacyJasyptPasswordEncryptor.newInstance());
         systemContextUsingCurrentWithLegacyFallbackEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        transitioningPasswordEncryptor);
         systemContextUsingCurrentWithLegacyFallbackEncryptor.authenticate(SYS_RESOURCE,
                                                                           PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

         // the tests below use one of the user context encryptors below
         userContextUsingCurrentWithLegacyFallbackEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        transitioningPasswordEncryptor);
         userContextUsingCurrentEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        jasyptPasswordEncryptor);
      }

      resourceExternalId = generateUniqueExternalId();
      resourceClassName = generateAuthenticatableResourceClass();
      resourceDomainName = generateDomain();
      resourceCredentials = PasswordCredentials.newInstance(generateRandomPassword().toCharArray());
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingLegacyEncryptor() throws Exception {
      final Resource resource = systemContextUsingLegacyEncryptor.createResource(resourceClassName,
                                                                                 resourceDomainName,
                                                                                 resourceExternalId,
                                                                                 resourceCredentials);

      userContextUsingLegacyEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingCurrentWithLegacyFallbackEncryptor() throws Exception {
      final Resource resource = systemContextUsingLegacyEncryptor.createResource(resourceClassName,
                                                                                 resourceDomainName,
                                                                                 resourceExternalId,
                                                                                 resourceCredentials);

      userContextUsingCurrentWithLegacyFallbackEncryptor.authenticate(resource, resourceCredentials);
   }

   @Test
   public void testAuthenticateOfResourceWithCurrentPasswordUsingCurrentEncryptor() throws Exception {
      final Resource resource = systemContextUsingCurrentWithLegacyFallbackEncryptor.createResource(resourceClassName,
                                                                                                    resourceDomainName,
                                                                                                    resourceExternalId,
                                                                                                    resourceCredentials);

      userContextUsingCurrentEncryptor.authenticate(resource, resourceCredentials);
   }

   private String generateAuthenticatableResourceClass() {
      final String resourceClassName = generateUniqueResourceClassName();
      systemContextUsingLegacyEncryptor.createResourceClass(resourceClassName, true, false);
      return resourceClassName;
   }

   private String generateDomain() {
      final String domainName = generateUniqueDomainName();
      systemContextUsingLegacyEncryptor.createDomain(domainName);
      return domainName;
   }

   private static String generateRandomPassword() {
      return "pwd_" + Math.random();
   }
}
