/*
 * Copyright 2009-2015, Acciente LLC
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

import com.acciente.oacc.helper.Constants;
import com.acciente.oacc.helper.TestDataSourceFactory;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.internal.SQLPasswordAuthenticationProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_authenticateWithCustomAuthenticationProvider extends TestAccessControlBase {

   public static final char[] GUEST_PASSWORD = "9UE5T".toCharArray();
   private static AccessControlContext customAccessControlContext;
   private static Resource             guestResource;

   @Before
   public void setUpTest() throws Exception {
      guestResource = generateAuthenticatableResource(GUEST_PASSWORD, generateDomain());

      SQLDialect sqlDialect = TestDataSourceFactory.getSQLDialect();
      DataSource dataSource = TestDataSourceFactory.getDataSource();
      customAccessControlContext
            = SQLAccessControlContextFactory.getAccessControlContext(dataSource,
                                                                     Constants.DB_SCHEMA,
                                                                     sqlDialect,
                                                                     new CustomAuthenticationProvider(dataSource,
                                                                                                      Constants.DB_SCHEMA,
                                                                                                      sqlDialect));
   }

   @After
   public void tearDownTest() throws Exception {
      customAccessControlContext.unauthenticate(); // because it doesn't hurt, in case we authenticated during a test
   }

   @Test
   public void authenticateSystemUser_custom_shouldFail() throws AccessControlException, SQLException {
      Resource systemAuthResource = getSystemResource();
      try {
         customAccessControlContext.authenticate(systemAuthResource,
                                                 PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
         fail("authenticating as system resource should have failed for custom authentication provider");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system resource authentication is not supported"));
      }
   }

   @Test
   public void authenticate_withoutCredentials_shouldSucceed() throws AccessControlException {
      customAccessControlContext.authenticate(guestResource);

      // verify
      assertThat(customAccessControlContext.getAuthenticatedResource(), is(guestResource));
      assertThat(customAccessControlContext.getSessionResource(), is(guestResource));

      // authenticate again
      customAccessControlContext.authenticate(guestResource);
   }

   private static class CustomAuthenticationProvider extends SQLPasswordAuthenticationProvider {
      protected CustomAuthenticationProvider(Connection connection,
                                             String schemaName,
                                             SQLDialect sqlDialect) throws AccessControlException {
         super(connection, schemaName, sqlDialect);
      }

      protected CustomAuthenticationProvider(DataSource dataSource,
                                             String schemaName,
                                             SQLDialect sqlDialect) throws AccessControlException {
         super(dataSource, schemaName, sqlDialect);
      }

      @Override
      public void authenticate(Resource resource, Credentials credentials) throws AccessControlException {
         if (SYS_RESOURCE.equals(resource)) {
            throw new AccessControlException("system resource authentication is not supported");
         }

         super.authenticate(resource, credentials);
      }

      @Override
      public void authenticate(Resource resource) throws AccessControlException {
         if (guestResource != null && guestResource.equals(resource)) {
            super.authenticate(guestResource, PasswordCredentials.newInstance(GUEST_PASSWORD));
         }
         else if (SYS_RESOURCE.equals(resource)) {
            throw new AccessControlException("system resource authentication is not supported");
         }
         else {
            super.authenticate(resource);
         }
      }

      @Override
      public void validateCredentials(Credentials credentials) throws AccessControlException {
         super.validateCredentials(credentials);
      }

      @Override
      public void setCredentials(Resource resource, Credentials credentials) throws AccessControlException {
         if (SYS_RESOURCE.equals(resource)) {
            throw new AccessControlException("setting credentials of system resource is not supported");
         }
         else if (guestResource != null && guestResource.equals(resource)) {
            throw new AccessControlException("setting credentials of guest resource is not supported");
         }

         super.setCredentials(resource, credentials);
      }
   }
}
