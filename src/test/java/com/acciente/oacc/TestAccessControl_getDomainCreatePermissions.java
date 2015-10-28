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

import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void getDomainCreatePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getDomainCreatePermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getDomainCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getDomainCreatePermissions_withExtId() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set domain create permissions
      final String externalId = generateUniqueExternalId();
      Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getDomainCreatePermissions(Resources.getInstance(externalId));
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getDomainCreatePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // authenticate without query authorization
      generateResourceAndAuthenticate();

      // get domain create permissions and verify
      try {
         accessControlContext.getDomainCreatePermissions(accessorResource);
         fail("getting domain create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getDomainCreatePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getDomainCreatePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // authenticate with query authorization
      final char[] password = generateUniquePassword();
      Resource authenticatableResource = generateAuthenticatableResource(password);
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getDomainCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getDomainCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String donorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String accessorPermissionName_createChild = donorPermissionName_createChild;
      final String accessorPermissionName_superUser = donorPermissionName_superUser;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                        true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, false),
                                                        false));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild, false),
                                                        false),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(accessorPermissionName_superUser, true),
                                                        true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(accessorPermissions));
   }

   @Test
   public void getDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getDomainCreatePermissions(null);
         fail("getting domain create permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getDomainCreatePermissions(Resources.getInstance(null));
         fail("getting domain create permissions for null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }

   @Test
   public void getDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getDomainCreatePermissions(invalidResource);
         fail("getting domain create permissions with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainCreatePermissions(invalidExternalResource);
         fail("getting domain create permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getDomainCreatePermissions(mismatchedResource);
         fail("getting domain create permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
