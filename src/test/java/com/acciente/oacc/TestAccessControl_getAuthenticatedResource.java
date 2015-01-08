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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getAuthenticatedResource extends TestAccessControlBase {
   @Test
   public void getAuthenticatedResource_authenticated_asSystemResource() throws AccessControlException {
      authenticateSystemResource();

      // verify
      final Resource authenticatedResource = accessControlContext.getAuthenticatedResource();
      assertThat(authenticatedResource, is(SYS_RESOURCE));
   }

   @Test
   public void getAuthenticatedResource_authenticated_asNonSystemResource() throws AccessControlException {
      // set up
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      // authenticate
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      final Resource authenticatedResource = accessControlContext.getAuthenticatedResource();
      assertThat(authenticatedResource, is(authenticatableResource));
   }

   @Test
   public void getAuthenticatedResource_impersonated() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // set up permission: accessor --IMPERSONATE-> impersonated
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate & impersonate
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));
      accessControlContext.impersonate(impersonatedResource);

      // verify
      final Resource authenticatedResource = accessControlContext.getAuthenticatedResource();
      assertThat(authenticatedResource, is(accessorResource));
   }

   @Test
   public void getAuthenticatedResource_notAuthenticated_shouldFail() throws AccessControlException {
      try {
         accessControlContext.getAuthenticatedResource();
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
   }
}
