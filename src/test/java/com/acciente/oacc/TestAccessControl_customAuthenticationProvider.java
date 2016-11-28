/*
 * Copyright 2009-2016, Acciente LLC
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

import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.SQLPasswordAuthenticationProvider;
import com.acciente.oacc.sql.internal.encryptor.JasyptPasswordEncryptor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.sql.DataSource;
import java.sql.Connection;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_customAuthenticationProvider extends TestAccessControlBase {

   public static final char[] GUEST_PASSWORD = "9UE5T".toCharArray();
   public static final char[] ADMIN_PASSWORD = "... . -.-. .-. . -".toCharArray();
   private static AccessControlContext customAccessControlContext;
   private static Resource             guestResource;
   private static Resource             adminResource;
   private static String               adminDomain;
   private static String               strictDomain;
   private static String               strictResourceClass;
   private static int                  strictMinPasswordLength = 16;

   @Before
   public void setUpTest() throws Exception {
      guestResource = generateAuthenticatableResource(GUEST_PASSWORD, generateDomain());
      adminDomain = generateDomain();
      adminResource = generateAuthenticatableResource(ADMIN_PASSWORD, adminDomain);
      strictDomain = generateChildDomain(adminDomain);
      strictResourceClass = generateResourceClass(true, false);

      authenticateSystemAccessControlContext();
      systemAccessControlContext.setDomainPermissions(adminResource,
                                                      adminDomain,
                                                      setOf(DomainPermissions
                                                                  .getInstance(DomainPermissions.SUPER_USER)));
      systemAccessControlContext.unauthenticate();

      SQLProfile sqlProfile = TestConfigLoader.getSQLProfile();
      DataSource dataSource = TestConfigLoader.getDataSource();
      customAccessControlContext
            = SQLAccessControlContextFactory.getAccessControlContext(dataSource,
                                                                     TestConfigLoader.getDatabaseSchema(),
                                                                     sqlProfile,
                                                                     new CustomAuthenticationProvider(dataSource,
                                                                                                      TestConfigLoader
                                                                                                            .getDatabaseSchema(),
                                                                                                      sqlProfile.getSqlDialect()));
   }

   @After
   public void tearDownTest() throws Exception {
      customAccessControlContext.unauthenticate(); // because it doesn't hurt, in case we authenticated during a test
   }

   @Test
   public void authenticateSystemUser_custom_shouldFail() {
      Resource systemAuthResource = getSystemResource();
      try {
         customAccessControlContext.authenticate(systemAuthResource,
                                                 PasswordCredentials.newInstance(TestConfigLoader.getOaccRootPassword()));
         fail("authenticating as system resource should have failed for custom authentication provider");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system resource authentication is not supported"));
      }
   }

   @Test
   public void authenticate_withoutCredentials_shouldSucceed() {
      customAccessControlContext.authenticate(guestResource);

      // verify
      assertThat(customAccessControlContext.getAuthenticatedResource(), is(guestResource));
      assertThat(customAccessControlContext.getSessionResource(), is(guestResource));

      // authenticate again
      customAccessControlContext.authenticate(guestResource);
   }

   @Test
   public void createResource_withoutCredentials_shouldFail() {
      customAccessControlContext.authenticate(adminResource, PasswordCredentials.newInstance(ADMIN_PASSWORD));

      final Resource resource
            = customAccessControlContext.createResource(generateResourceClass(true, true),
                                                        customAccessControlContext.getDomainNameByResource(adminResource));
      assertThat(resource, is(not(nullValue())));
   }

   @Test
   public void createResource_validCredentialCriteria_shouldSucceed() {
      customAccessControlContext.authenticate(adminResource, PasswordCredentials.newInstance(ADMIN_PASSWORD));

      final Resource strictAuthenticatableResource
            = customAccessControlContext.createResource(strictResourceClass,
                                                        strictDomain,
                                                        PasswordCredentials.newInstance("opensesameplease".toCharArray()));
      assertThat(strictAuthenticatableResource, is(not(nullValue())));
   }

   @Test
   public void createResource_invalidCredentialCriteria_shouldFail() {
      customAccessControlContext.authenticate(adminResource, PasswordCredentials.newInstance(ADMIN_PASSWORD));

      try {
         customAccessControlContext.createResource(strictResourceClass,
                                                   strictDomain,
                                                   PasswordCredentials.newInstance("tooshort".toCharArray()));
         fail("creating resource with invalid credentials should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not meet minimum length"));
      }
   }

   @Test
   public void setCredentials_validCredentialCriteria_shouldSucceed() {
      customAccessControlContext.authenticate(adminResource, PasswordCredentials.newInstance(ADMIN_PASSWORD));

      final Resource strictAuthenticatableResource
            = customAccessControlContext.createResource(strictResourceClass,
                                                        strictDomain,
                                                        PasswordCredentials.newInstance("opensesameplease".toCharArray()));

      final PasswordCredentials newCredentials = PasswordCredentials.newInstance("pleaseopensesame".toCharArray());
      customAccessControlContext.setCredentials(strictAuthenticatableResource, newCredentials);

      customAccessControlContext.authenticate(strictAuthenticatableResource, newCredentials);
   }

   @Test
   public void setCredentials_invalidCredentialCriteria_shouldFail() {
      customAccessControlContext.authenticate(adminResource, PasswordCredentials.newInstance(ADMIN_PASSWORD));

      final Resource strictAuthenticatableResource
            = customAccessControlContext.createResource(strictResourceClass,
                                                        strictDomain,
                                                        PasswordCredentials.newInstance("opensesameplease".toCharArray()));

      try {
         customAccessControlContext.setCredentials(strictAuthenticatableResource,
                                                   PasswordCredentials.newInstance("tooshort".toCharArray()));
         fail("setting credentials with invalid credentials should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not meet minimum length"));
      }
   }

   private static class CustomAuthenticationProvider extends SQLPasswordAuthenticationProvider {
      protected CustomAuthenticationProvider(Connection connection,
                                             String schemaName,
                                             SQLDialect sqlDialect) {
         super(connection, schemaName, sqlDialect, new JasyptPasswordEncryptor());
      }

      protected CustomAuthenticationProvider(DataSource dataSource,
                                             String schemaName,
                                             SQLDialect sqlDialect) {
         super(dataSource, schemaName, sqlDialect, new JasyptPasswordEncryptor());
      }

      @Override
      public void authenticate(Resource resource, Credentials credentials) {
         if (SYS_RESOURCE.equals(resource)) {
            throw new IllegalArgumentException("system resource authentication is not supported");
         }

         super.authenticate(resource, credentials);
      }

      @Override
      public void authenticate(Resource resource) {
         if (guestResource != null && guestResource.equals(resource)) {
            super.authenticate(guestResource, PasswordCredentials.newInstance(GUEST_PASSWORD));
         }
         else if (SYS_RESOURCE.equals(resource)) {
            throw new IllegalArgumentException("system resource authentication is not supported");
         }
         else {
            super.authenticate(resource);
         }
      }

      @Override
      public void validateCredentials(String resourceClassName, String domainName, Credentials credentials) {
         // unlike super.validateCredentials(), our custom validator passes if credentials are null
         if (credentials != null) {
            if (credentials instanceof PasswordCredentials
                  && strictResourceClass.equalsIgnoreCase(resourceClassName)
                  && strictDomain.equalsIgnoreCase(domainName)
                  && ((PasswordCredentials) credentials).getPassword().length < strictMinPasswordLength) {
               throw new InvalidCredentialsException("password does not meet minimum length criteria (" + strictMinPasswordLength + ")");
            }

            super.validateCredentials(resourceClassName, domainName, credentials);
         }
      }

      @Override
      public void setCredentials(Resource resource, Credentials credentials) {
         if (SYS_RESOURCE.equals(resource)) {
            throw new IllegalArgumentException("setting credentials of system resource is not supported");
         }
         else if (guestResource != null && guestResource.equals(resource)) {
            throw new IllegalArgumentException("setting credentials of guest resource is not supported");
         }

         super.setCredentials(resource, credentials);
      }

      @Override
      public void deleteCredentials(Resource resource) {
         if (SYS_RESOURCE.equals(resource)) {
            throw new IllegalArgumentException("deleting credentials of system resource is not supported");
         }
         else if (guestResource != null && guestResource.equals(resource)) {
            throw new IllegalArgumentException("deleting credentials of guest resource is not supported");
         }

         super.deleteCredentials(resource);
      }
   }
}
