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
import static org.junit.Assert.fail;

public class TestAccessControl_hasDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void hasDomainCreatePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      // verify setup
      final Set<DomainCreatePermission> allDomainCreatePermissions
            = accessControlContext.getEffectiveDomainCreatePermissions(SYS_RESOURCE);
      assertThat(allDomainCreatePermissions.isEmpty(), is(false));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                            true))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                                            true))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true))) {
         fail("checking implicit domain create permission with and without grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
                                                                                  DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                            true),
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
                                              DomainPermissions.SUPER_USER)))) {
         fail("checking implicit domain create permission with multiple permissions should have succeeded for system resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_noPermissions_shouldFailAsAuthenticated() {
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
      if (accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                          DomainCreatePermissions
                                                                .getInstance(DomainCreatePermissions.CREATE))) {
         fail("checking domain create permission when none has been granted should not have succeeded for authenticated resource");
      }
      if (accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                          DomainCreatePermissions
                                                                .getInstance(DomainCreatePermissions.CREATE),
                                                          DomainCreatePermissions
                                                                .getInstance(DomainPermissions
                                                                                   .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking domain create permissions when none have been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(
                                                                       DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permissions with multiple permissions should have succeeded for authenticated resource");
      }
      if (accessControlContext
               .hasDomainCreatePermissions(accessorResource,
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)),
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(DomainPermissions.SUPER_USER)))) {
         fail("checking direct domain create permissions with partial authorization should have failed for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE,
                                                        false),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      false)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                      false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(DomainPermissions.SUPER_USER)),
                                           DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(
                                                                          DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permissions with all permissions should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permission with same granting rights should have succeeded for authenticated resource");
      }
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
                                              DomainPermissions.CREATE_CHILD_DOMAIN,
                                              true)))) {
         fail("checking direct domain create permission with exceeded granting rights should have failed for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking inherited domain create permission should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_superUser_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)))) {
         fail("checking direct super-user domain create permission should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true)))) {
         fail("checking direct super-user /G domain create permission should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking create-child-domain domain create permission when only super-user domain create permission is given should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true)))) {
         fail("checking create-child-domain /G domain create permission when only super-user domain create permission is given should have failed for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(accessorPermissionName_createChild, true),
                                                           true))) {
         fail("checking inherited domain create permission with different granting rights should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false),
                                                           true),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                           false),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false),
                                                           false))) {
         fail("checking domain create permission inherited from two sources with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                           true))) {
         fail("checking domain create permission inherited from two sources with different granting rights should have failed for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_multiLevelInheritance_shouldSucceedAsAuthorized() {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                           false),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, false),
                                                           true))) {
         fail("checking double-inherited domain create permission with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild, true),
                                                           true))) {
         fail("checking double-inherited domain create permission with different granting rights should have failed for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() {
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
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(donorPermissionName_createDomain)));

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createDomain)))) {
         fail("checking domain create permission inherited with empty intermediary level should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      try {
         accessControlContext.hasDomainCreatePermissions(null, domainCreatePermission);
         fail("checking domain create permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, null);
         fail("checking domain create permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain create permission required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, new DomainCreatePermission[] {null});
         fail("checking domain create permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, domainCreatePermission, null);
         fail("checking domain create permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
   }

   @Test
   public void hasDomainCreatePermission_emptyPermissions_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource);
         fail("checking domain create permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, new DomainCreatePermission[]{});
         fail("checking domain create permission with empty permission sequence should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
   }

   @Test
   public void hasDomainCreatePermission_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                      domainCreatePermission,
                                                      domainCreatePermission);
   }

   @Test
   public void hasDomainCreatePermissions_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      if (accessControlContext.hasDomainCreatePermissions(invalidResource, domainCreatePermission)){
         // the check will "succeed" in the sense that it will fail to assert the permission on the
         // invalid resource, since that resource does not have the specified permission
         fail("checking domain create permission with invalid accessor resource should have failed");
      }
   }
}
