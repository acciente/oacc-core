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

public class TestAccessControl_JasyptEncryptorIncludingBackwardsCompatibility {
   private static final Resource SYS_RESOURCE = Resources.getInstance(0);

   private AccessControlContext systemAccessControlContextWithLegacyEncryptor;
   private AccessControlContext systemAccessControlContextWithCurrentEncryptor;

   private AccessControlContext accessControlContextWithLegacyEncryptor;
   private AccessControlContext accessControlContextWithCurrentEncryptor;
   private String               resourceExternalId;
   private String               resourceClassName;
   private String               resourceDomainName;
   private PasswordCredentials  resourceCredentials;

   @Before
   public void setUpTest() throws Exception {
      // uses the legacy built-in password encryptor code (from OACC v2.00 rc7 and before)
      {
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

      // this uses the latest Jasypt password encryptor code
      {
         // we use values different values from the default
         final JasyptPasswordEncryptor jasyptPasswordEncryptor = JasyptPasswordEncryptor.getPasswordEncryptor("MD5", 2000, 32);
         systemAccessControlContextWithCurrentEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        jasyptPasswordEncryptor);
         systemAccessControlContextWithCurrentEncryptor.authenticate(SYS_RESOURCE,
                                                                     PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));

         accessControlContextWithCurrentEncryptor
               = SQLAccessControlContextFactory.getAccessControlContext(TestConfigLoader.getDataSource(),
                                                                        TestConfigLoader.getDatabaseSchema(),
                                                                        TestConfigLoader.getSQLProfile(),
                                                                        jasyptPasswordEncryptor);
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
      System.out.printf("created resource %s (using legacy encryptor)\n", resource);

      accessControlContextWithLegacyEncryptor.authenticate(resource, resourceCredentials);
      System.out.printf("authenticated resource %s (using legacy encryptor)\n", resource);
   }

   @Test
   public void testAuthenticateOfResourceWithLegacyPasswordUsingCurrentEncryptor() throws Exception {
      final Resource resource = systemAccessControlContextWithLegacyEncryptor.createResource(resourceClassName,
                                                                                             resourceDomainName,
                                                                                             resourceExternalId,
                                                                                             resourceCredentials);
      System.out.printf("created resource %s (using legacy encryptor)\n", resource);

      accessControlContextWithCurrentEncryptor.authenticate(resource, resourceCredentials);
      System.out.printf("authenticated resource %s (using new encryptor)\n", resource);
   }

   @Test
   public void testAuthenticateOfResourceWithCurrentPasswordUsingCurrentEncryptor() throws Exception {
      final Resource resource = systemAccessControlContextWithCurrentEncryptor.createResource(resourceClassName,
                                                                                              resourceDomainName,
                                                                                              resourceExternalId,
                                                                                              resourceCredentials);
      System.out.printf("created resource %s (using new encryptor)\n", resource);

      accessControlContextWithCurrentEncryptor.authenticate(resource, resourceCredentials);
      System.out.printf("authenticated resource %s (using new encryptor)\n", resource);
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
