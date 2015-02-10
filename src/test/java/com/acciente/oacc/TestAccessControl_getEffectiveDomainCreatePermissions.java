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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getEffectiveDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsAuthenticated() throws AccessControlException {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();

      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_validAsSystemResource() throws AccessControlException {
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
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
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
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
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
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true), true));
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, false), false));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild, false), false));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstance(DomainPermissions.getInstance(accessorPermissionName_superUser, true), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild, true), true));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(accessorPermissionName_superUser, true), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
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
      donor1Permissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, false), true));
      donor1Permissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true), false));

      accessControlContext.setDomainCreatePermissions(donor1Resource, donor1Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor1Resource), is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<DomainCreatePermission> donor2Permissions = new HashSet<>();
      donor2Permissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      donor2Permissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, true), true));
      donor2Permissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false), true));

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
                                     .getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, true), true));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false), true));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true), false));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_multiLevelInheritance_shouldSucceedAsAuthorized() throws AccessControlException {
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
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, true), true));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup inheritor domain create permissions
      Set<DomainCreatePermission> inheritorPermissions = new HashSet<>();
      inheritorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      inheritorPermissions.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(inheritorPermissionName_superUser, false),
                                                  true));
      inheritorPermissions.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(inheritorPermissionName_createDomain, true),
                                                  false));

      accessControlContext.setDomainCreatePermissions(inheritorResource, inheritorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(inheritorResource), is(inheritorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstance(DomainPermissions.getInstance(accessorPermissionName_createDomain),
                                                 true));

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
                                     .getInstance(DomainPermissions.getInstance(donorPermissionName_superUser, true), true));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(accessorPermissionName_createDomain, true), false));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(accessorPermissionName_createDomain, false), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() throws AccessControlException {
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
      donorPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // no inheritor domain create permissions to set up

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions.add(DomainCreatePermissions
                                    .getInstance(DomainPermissions.getInstance(accessorPermissionName_createDomain),
                                                 true));

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
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_superUser)));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(accessorPermissionName_createDomain), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveDomainCreatePermissions(null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
   }

   @Test
   public void getEffectiveDomainCreatePermissions_nonExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(invalidResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }
}
