/*
 * Copyright 2009-2018, Acciente LLC
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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_unimpersonate extends TestAccessControlBase {
   @Test
   public void unimpersonate_valid_asSystemResource() {
      authenticateSystemResource();

      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());
      accessControlContext.impersonate(impersonatedResource);

      // verify
      accessControlContext.unimpersonate();

      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));
   }

   @Test
   public void unimpersonate_unimpersonated_succeedsAsSystemResource() {
      authenticateSystemResource();

      generateAuthenticatableResource(generateUniquePassword());

      // verify
      accessControlContext.unimpersonate();

      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));
   }

   @Test
   public void unimpersonate_valid_asAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // set up accessor --IMPERSONATE-> impersonatedResource
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
      // authenticate & impersonate
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));
      accessControlContext.impersonate(impersonatedResource);

      // verify
      accessControlContext.unimpersonate();

      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(accessorResource));
   }

   @Test
   public void unimpersonate_unimpersonated_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // set up accessor --IMPERSONATE-> impersonatedResource
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
      // authenticate
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.unimpersonate();

      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(accessorResource));
   }

}
