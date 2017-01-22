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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_impersonate extends TestAccessControlBase {
   @Test
   public void impersonate_valid_asSystemResource() {
      authenticateSystemResource();

      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
   }

   @Test
   public void impersonate_valid_withExtId() {
      authenticateSystemResource();

      final String externalId = generateUniqueExternalId();
      final Resource impersonatedResource = generateAuthenticatableResourceWithExtId(generateUniquePassword(),
                                                                                     externalId);

      accessControlContext.impersonate(Resources.getInstance(externalId));
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
      assertThat(accessControlContext.getSessionResource().getExternalId(), is(externalId));
   }

   @Test
   public void impersonate_chainedImpersonation_succeedsAsSystemResource() {
      authenticateSystemResource();

      final Resource impersonatedResource1 = generateAuthenticatableResource(generateUniquePassword());
      final Resource impersonatedResource2 = generateAuthenticatableResource(generateUniquePassword());

      // impersonate
      accessControlContext.impersonate(impersonatedResource1);

      // chained impersonation should succeed because we use authenticated resource's authorization credentials
      accessControlContext.impersonate(impersonatedResource2);
      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource2));
   }

   @Test
   public void impersonate_valid_asAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // set up accessor --IMPERSONATE-> impersonatedResource
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
   }

   @Test
   public void impersonate_chainedImpersonation_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource1 = generateAuthenticatableResource(generateUniquePassword());
      final Resource impersonatedResource2 = generateAuthenticatableResource(generateUniquePassword());

      // set up accessor --IMPERSONATE-> impersonatedResource1
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource1,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // set up impersonatedResource1 --IMPERSONATE-> impersonatedResource2
      accessControlContext.setResourcePermissions(impersonatedResource1,
                                                  impersonatedResource2,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // impersonate
      accessControlContext.impersonate(impersonatedResource1);

      // chained impersonation should NOT succeed because we use authenticated resource's authorization credentials
      // and accessorResource doesn't have IMPERSONATE permission on impersonatedResource2
      try {
         accessControlContext.impersonate(impersonatedResource2);
         fail("chained impersonation without IMPERSONATE permission from authenticated resource to impersonated resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized to impersonate"));
      }
   }

   @Test
   public void impersonate_chainedImpersonationWithPermission_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource1 = generateAuthenticatableResource(generateUniquePassword());
      final Resource impersonatedResource2 = generateAuthenticatableResource(generateUniquePassword());

      // set up accessor --IMPERSONATE-> impersonatedResource1
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource1,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // set up accessor --IMPERSONATE-> impersonatedResource2
      accessControlContext.setResourcePermissions(accessorResource,
                                                  impersonatedResource2,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // impersonate
      accessControlContext.impersonate(impersonatedResource1);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource1));

      // valid chained impersonation
      accessControlContext.impersonate(impersonatedResource2);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource2));
   }

   @Test
   public void impersonate_unauthenticatable_shouldFailAsSystemResource() {
      authenticateSystemResource();

      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // attempt to impersonate
      try {
         accessControlContext.impersonate(unauthenticatableResource);
         fail("attempting to impersonate an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not of an authenticatable resource class"));
      }
   }

   @Test
   public void impersonate_unauthenticatable_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // attempt to impersonate
      try {
         accessControlContext.impersonate(unauthenticatableResource);
         fail("attempting to impersonate an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not of an authenticatable resource class"));
      }
   }

   @Test
   public void impersonate_notAuthorized_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // attempt to impersonate
      try {
         accessControlContext.impersonate(impersonatedResource);
         fail("impersonating a resource without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized to impersonate"));
      }
   }

   @Test
   public void impersonate_inherit_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword());

      // set up donor --IMPERSONATE-> impersonatedResource
      accessControlContext.setResourcePermissions(donorResource,
                                                  impersonatedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // set up accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
   }

   @Test
   public void impersonate_global_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String impersonatedDomain = generateDomain();
      final String impersonatedResourceClass = generateResourceClass(true, false);
      final Resource impersonatedResource
            = accessControlContext.createResource(impersonatedResourceClass,
                                                  impersonatedDomain,
                                                  PasswordCredentials.newInstance(generateUniquePassword()));

      // set up global permission: accessor --IMPERSONATE-> {impersonated resource class, impersonated domain}
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        impersonatedResourceClass,
                                                        impersonatedDomain,
                                                        setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
   }

   @Test
   public void impersonate_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String impersonatedDomain = generateDomain();
      final Resource impersonatedResource = generateAuthenticatableResource(generateUniquePassword(), impersonatedDomain);

      // set up super-user domain permission
      accessControlContext.setDomainPermissions(accessorResource,
                                                impersonatedDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      accessControlContext.impersonate(impersonatedResource);
      assertThat(accessControlContext.getAuthenticatedResource(), is(accessorResource));
      assertThat(accessControlContext.getSessionResource(), is(impersonatedResource));
   }

   @Test
   public void impersonate_nulls_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // attempt to impersonate
      try {
         accessControlContext.impersonate(null);
         fail("calling impersonate with a null resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.impersonate(Resources.getInstance(null));
         fail("calling impersonate with a null external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }

   @Test
   public void impersonate_nonExistentReference_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // attempt to impersonate
      try {
         accessControlContext.impersonate(Resources.getInstance(-999L));
         fail("calling impersonate with a non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.impersonate(Resources.getInstance("invalid"));
         fail("calling impersonate with a non-existent external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.impersonate(Resources.getInstance(-999L, "invalid"));
         fail("calling impersonate with a non-existent external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
