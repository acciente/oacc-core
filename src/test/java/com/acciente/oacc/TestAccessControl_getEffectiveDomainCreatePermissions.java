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

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getEffectiveDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_withExtId() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

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
            = accessControlContext.getEffectiveDomainCreatePermissions(Resources.getInstance(externalId));
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String donorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String accessorPermissionName_createChild = donorPermissionName_createChild;
      final String accessorPermissionName_superUser = donorPermissionName_superUser;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild)));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(accessorPermissionName_superUser)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(accessorPermissionName_createChild)));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(accessorPermissionName_superUser)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donor1Resource = generateUnauthenticatableResource();
      final Resource donor2Resource = generateUnauthenticatableResource();

      // setup donor 1 domain create permissions
      Set<DomainCreatePermission> donor1Permissions = new HashSet<>();
      donor1Permissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donor1Permissions.add(DomainCreatePermissions.getInstanceWithGrantOption(
            DomainPermissions.getInstance(donorPermissionName_superUser)));
      donor1Permissions.add(DomainCreatePermissions.getInstance(
            DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));

      accessControlContext.setDomainCreatePermissions(donor1Resource, donor1Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor1Resource), is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<DomainCreatePermission> donor2Permissions = new HashSet<>();
      donor2Permissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donor2Permissions.add(DomainCreatePermissions.getInstanceWithGrantOption(
            DomainPermissions.getInstanceWithGrantOption(donorPermissionName_superUser)));
      donor2Permissions.add(DomainCreatePermissions.getInstanceWithGrantOption(
            DomainPermissions.getInstance(donorPermissionName_createChild)));

      accessControlContext.setDomainCreatePermissions(donor2Resource, donor2Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor2Resource), is(donor2Permissions));

      // setup no accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor1
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donor1Resource, accessor2donorPermissions);

      // setup inheritor --INHERIT--> donor2
      accessControlContext.setResourcePermissions(accessorResource, donor2Resource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_superUser)));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstance(donorPermissionName_createChild)));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_multiLevelInheritance_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String inheritorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String inheritorPermissionName_createDomain = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String accessorPermissionName_createDomain = inheritorPermissionName_createDomain;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_superUser)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup inheritor domain create permissions
      Set<DomainCreatePermission> inheritorPermissions = new HashSet<>();
      inheritorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      inheritorPermissions.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstance(inheritorPermissionName_superUser)));
      inheritorPermissions.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstanceWithGrantOption(inheritorPermissionName_createDomain)));

      accessControlContext.setDomainCreatePermissions(inheritorResource, inheritorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(inheritorResource), is(inheritorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstanceWithGrantOption(DomainPermissions.getInstance(accessorPermissionName_createDomain)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = new HashSet<>();
      inheritor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = new HashSet<>();
      accessor2inheritorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_superUser)));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstanceWithGrantOption(accessorPermissionName_createDomain)));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstanceWithGrantOption(DomainPermissions.getInstance(accessorPermissionName_createDomain)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_superUser = DomainPermissions.SUPER_USER;
      final String accessorPermissionName_createDomain = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            donorPermissionName_superUser)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // no inheritor domain create permissions to set up

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstanceWithGrantOption(DomainPermissions.getInstance(accessorPermissionName_createDomain)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = new HashSet<>();
      inheritor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = new HashSet<>();
      accessor2inheritorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            donorPermissionName_superUser)));
      permissions_expected.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(
            accessorPermissionName_createDomain)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

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
         accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
         fail("getting effective domain create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getEffectiveDomainCreatePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // authenticate with implicit query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // set domain create permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // authenticate with query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveDomainCreatePermissions(null);
         fail("getting effective domain create permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveDomainCreatePermissions(Resources.getInstance(null));
         fail("getting effective domain create permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }

   @Test
   public void getEffectiveDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getEffectiveDomainCreatePermissions(invalidResource);
         fail("getting effective domain create permissions with invalid resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainCreatePermissions(invalidExternalResource);
         fail("getting effective domain create permissions with invalid external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveDomainCreatePermissions(mismatchedResource);
         fail("getting effective domain create permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
