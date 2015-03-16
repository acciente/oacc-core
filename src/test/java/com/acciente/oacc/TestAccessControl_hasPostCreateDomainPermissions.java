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

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasPostCreateDomainPermissions extends TestAccessControlBase {
   @Test
   public void hasPostCreateDomainPermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      // verify setup
      final Set<DomainCreatePermission> allDomainCreatePermissions
            = accessControlContext.getEffectiveDomainCreatePermissions(SYS_RESOURCE);
      assertThat(allDomainCreatePermissions.isEmpty(), is(false));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(SYS_RESOURCE,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking implicit post-create domain permission should have succeeded as system resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(SYS_RESOURCE,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                             true))) {
         fail("checking implicit post-create domain permission with grant should have succeeded as system resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(SYS_RESOURCE,
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER))) {
         fail("checking implicit post-create domain permission should have succeeded as system resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(SYS_RESOURCE,
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                             true))) {
         fail("checking implicit post-create domain permission with grant should have succeeded as system resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(SYS_RESOURCE,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                             true),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                             true))) {
         fail("checking all implicit post-create domain permission with grant should have succeeded as system resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                             true),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                             true))) {
         fail("checking all implicit post-create domain permission with grant should have succeeded as implicit system resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // verify setup
      final Set<DomainCreatePermission> allDomainCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(allDomainCreatePermissionsForResourceClass.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking post-create domain permission when none has been granted should not have succeeded for implicit authenticated resource");
      }
      if (accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking post-create domain permission when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                            true))) {
         fail("checking post-create domain permissions when none have been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking direct post-create domain permission should have succeeded for implicit authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking direct post-create domain permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking direct post-create domain permission should have succeeded for authenticated resource");
      }

      // verify
      if (accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                            true))) {
         fail("checking direct and unauthorized post-create domain permission should have failed for implicit authenticated resource");
      }
      if (accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                            true))) {
         fail("checking direct and unauthorized post-create domain permission should have failed for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_multipleDirect_shouldSucceedAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, false),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      false)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                      false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER))) {
         fail("checking multiple direct post-create domain permission should have succeeded for implicit authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER))) {
         fail("checking multiple direct post-create domain permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE,
                                                        false),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // verify permissions
      final Set<DomainCreatePermission> allDomainCreatePermissions
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(allDomainCreatePermissions, is(domainCreatePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking direct post-create domain permission without grant should have succeeded for implicit authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking direct post-create domain permission without grant should have succeeded for authenticated resource");
      }

      if (accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                            true))) {
         fail("checking direct post-create domain permission for a permission with exceeded granting rights should have failed");
      }
      if (accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                              DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                            true))) {
         fail("checking direct post-create domain permission for a permission with exceeded granting rights should have failed");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource intermediaryResource = generateUnauthenticatableResource();

      // setup create permissions
      grantDomainAndChildCreatePermission(intermediaryResource);
      // setup inheritance permission
      accessControlContext.setResourcePermissions(accessorResource,
                                                  intermediaryResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking inherited post-create domain permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup super-user domain create permission
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, false),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER, false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER))) {
         fail("checking implicit post-create domain permission when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                             true))) {
         fail("checking implicit post-create domain permission with grant when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))) {
         fail("checking implicit post-create domain permission when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                             true))) {
         fail("checking implicit post-create domain permission with grant when having super-user privileges should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                               DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                             true),
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                               DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                             true))) {
         fail("checking multiple implicit post-create domain permission with grant when having super-user privileges should have succeeded for implicit authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String accessorPermissionName_createChild = donorPermissionName_createChild;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                        true));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild, false),
                                                        false));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(accessorPermissionName_createChild,
                                                                     true))) {
         fail("checking inherited post-create domain permission in presence of permission with differing granting right should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(accessorPermissionName_createChild),
                                                               DomainPermissions.getInstance(accessorPermissionName_createChild,
                                                                     true))) {
         fail("checking multiple inherited post-create domain permission in presence of permission with differing granting right should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donor1Resource = generateUnauthenticatableResource();
      final Resource donor2Resource = generateUnauthenticatableResource();

      // setup donor 1 domain create permissions
      Set<DomainCreatePermission> donor1Permissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                        false));

      accessControlContext.setDomainCreatePermissions(donor1Resource, donor1Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor1Resource), is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<DomainCreatePermission> donor2Permissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false),
                                                        true));

      accessControlContext.setDomainCreatePermissions(donor2Resource, donor2Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor2Resource), is(donor2Permissions));

      // setup no accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor1
      Set<ResourcePermission> accessor2donorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donor1Resource, accessor2donorPermissions);

      // setup inheritor --INHERIT--> donor2
      accessControlContext.setResourcePermissions(accessorResource, donor2Resource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                             true))) {
         fail("checking post-create domain permission inherited from two resources with differing granting rights should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(donorPermissionName_createChild),
                                                               DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                             true))) {
         fail("checking multiple post-create domain permission inherited from two resources with differing granting rights should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(DomainPermissions.getInstance(donorPermissionName_createChild),
                                                               DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                             true))) {
         fail("checking multiple post-create domain permission inherited from two resources with differing granting rights should have succeeded for implicit authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_multiLevelInheritance_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String inheritorPermissionName_createChild = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                      true)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup inheritor domain create permissions
      Set<DomainCreatePermission> inheritorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(inheritorPermissionName_createChild, false),
                                                        true));

      accessControlContext.setDomainCreatePermissions(inheritorResource, inheritorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(inheritorResource), is(inheritorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                             true))) {
         fail("checking multi-level inherited post-create domain permission should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(donorPermissionName_createChild),
                                                               DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                             true))) {
         fail("checking multiple multi-level inherited post-create domain permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String donorPermissionName_createDomain = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();

      // setup donor domain create permissions
      Set<DomainCreatePermission> donorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createDomain)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // no inheritor domain create permissions to set up

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      if (!accessControlContext.hasPostCreateDomainPermissions(accessorResource,
                                                               DomainPermissions.getInstance(donorPermissionName_createDomain))) {
         fail("checking multi-level inherited post-create domain permission with empty intermediary level should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      try {
         accessControlContext.hasPostCreateDomainPermissions((Resource) null, domainPermission);
         fail("checking post-create domain permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(null);
         fail("checking post-create domain permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(accessorResource, null);
         fail("checking post-create domain permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(accessorResource, new DomainPermission[] {null});
         fail("checking post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(new DomainPermission[] {null});
         fail("checking post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(accessorResource, domainPermission, null);
         fail("checking post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(domainPermission, null);
         fail("checking post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_emptyPermissions_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.hasPostCreateDomainPermissions();
         fail("checking post-create domain permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(accessorResource);
         fail("checking post-create domain permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(accessorResource, new DomainPermission[] {});
         fail("checking post-create domain permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.hasPostCreateDomainPermissions(new DomainPermission[] {});
         fail("checking post-create domain permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // setup permission for accessor
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      setOf(DomainCreatePermissions
                                                                  .getInstance(DomainCreatePermissions.CREATE),
                                                            DomainCreatePermissions.getInstance(domainPermission)));

      // verify
      if (!accessControlContext.hasPostCreateDomainPermissions(domainPermission, domainPermission)) {
         fail("checking post create domain permission with duplicate permissions should have succeeded");
      }
      if(!accessControlContext.hasPostCreateDomainPermissions(accessorResource, domainPermission, domainPermission)) {
         fail("checking post create domain permission with duplicate permissions should have succeeded");
      }
   }

   @Test
   public void hasPostCreateDomainPermissions_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      if (accessControlContext.hasPostCreateDomainPermissions(invalidResource, domainPermission)) {
         // the check will "succeed" in the sense that it will fail to assert the permission on the
         // invalid resource, since that resource does not have the specified permission
         fail("checking post-create domain permission with invalid accessor resource should have failed");
      }
   }
}
