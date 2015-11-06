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

import java.util.Collections;
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
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.DELETE)))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.DELETE)))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)))) {
         fail("checking implicit domain create permission should have succeeded for system resource");
      }
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)))) {
         fail("checking implicit domain create permission with grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE))) {
         fail("checking implicit domain create permission with and without grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(
                                                                                  DomainPermissions.CREATE_CHILD_DOMAIN)),
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
                                              DomainPermissions.SUPER_USER)))) {
         fail("checking implicit domain create permission with multiple permissions should have succeeded for system resource");
      }

      // test set-based versions
      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE)))) {
         fail("checking implicit domain create permission with and without grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE)))) {
         fail("checking implicit domain create permission with and without grant should have succeeded for system resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(SYS_RESOURCE,
                                        setOf(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(
                                                                                        DomainPermissions.CREATE_CHILD_DOMAIN)),
                                              DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
                                                    DomainPermissions.SUPER_USER))))) {
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
      if (accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                          setOf(DomainCreatePermissions
                                                                      .getInstance(DomainCreatePermissions.CREATE),
                                                                DomainCreatePermissions
                                                                      .getInstance(DomainPermissions
                                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
         fail("checking domain create permissions when none have been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_direct_withExtId() {
      authenticateSystemResource();

      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(Resources.getInstance(externalId),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permission should have succeeded for external resource id");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(Resources.getInstance(externalId),
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
         fail("checking direct domain create permission should have succeeded for external resource id");
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

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
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

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.SUPER_USER))))) {
         fail("checking direct domain create permissions with partial authorization should have failed for implicit authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions
                                                              .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

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

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.SUPER_USER)),
                                              DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(
                                                                             DomainPermissions.CREATE_CHILD_DOMAIN))))) {
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
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));

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
                                        DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(
                                              DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking direct domain create permission with exceeded granting rights should have failed for authenticated resource");
      }

      // test set-based version
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
         fail("checking direct domain create permission with same granting rights should have succeeded for authenticated resource");
      }
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
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
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
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
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

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
                                              .getInstance(DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER)))) {
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
                                                                 .getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking create-child-domain /G domain create permission when only super-user domain create permission is given should have failed for authenticated resource");
      }

      // test set-based version
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER))))) {
         fail("checking direct super-user /G domain create permission should have failed for authenticated resource");
      }
      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
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
                    DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup accessor domain create permissions
      Set<DomainCreatePermission> accessorPermissions
            = setOf(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions
                                                              .getInstance(accessorPermissionName_createChild)));

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
                                              .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(
                                                    accessorPermissionName_createChild)))) {
         fail("checking inherited domain create permission with different granting rights should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(
                                                          accessorPermissionName_createChild))))) {
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
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));

      accessControlContext.setDomainCreatePermissions(donor1Resource, donor1Permissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donor1Resource), is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<DomainCreatePermission> donor2Permissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(donorPermissionName_createChild)));

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
                                              .getInstanceWithGrantOption(DomainPermissions.getInstance(donorPermissionName_createChild)),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)),
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(donorPermissionName_createChild)))) {
         fail("checking domain create permission inherited from two sources with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)))) {
         fail("checking domain create permission inherited from two sources with different granting rights should have failed for authenticated resource");
      }

      // test set-based versions
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstanceWithGrantOption(DomainPermissions.getInstance(
                                                          donorPermissionName_createChild)),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstanceWithGrantOption(
                                                          donorPermissionName_createChild)),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(
                                                          donorPermissionName_createChild))))) {
         fail("checking domain create permission inherited from two sources with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(
                                                          donorPermissionName_createChild))))) {
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
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)));

      accessControlContext.setDomainCreatePermissions(donorResource, donorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(donorResource), is(donorPermissions));

      // setup inheritor domain create permissions
      Set<DomainCreatePermission> inheritorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(inheritorPermissionName_createChild)));

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
                                              .getInstance(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)), DomainCreatePermissions
                                              .getInstanceWithGrantOption(DomainPermissions.getInstance(donorPermissionName_createChild)))) {
         fail("checking double-inherited domain create permission with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(donorPermissionName_createChild)))) {
         fail("checking double-inherited domain create permission with different granting rights should have failed for authenticated resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstanceWithGrantOption(
                                                          donorPermissionName_createChild)),
                                              DomainCreatePermissions
                                                    .getInstanceWithGrantOption(DomainPermissions.getInstance(
                                                          donorPermissionName_createChild))))) {
         fail("checking double-inherited domain create permission with different granting rights should have succeeded for authenticated resource");
      }

      if (accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(
                                                          donorPermissionName_createChild))))) {
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

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions.getInstance(
                                                    donorPermissionName_createDomain)))) {
         fail("checking domain create permission inherited with empty intermediary level should have succeeded for authenticated resource");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(donorPermissionName_createDomain))))) {
         fail("checking domain create permission inherited with empty intermediary level should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasDomainCreatePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext
               .hasDomainCreatePermissions(accessorResource,
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("checking domain create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext
               .hasDomainCreatePermissions(accessorResource,
                                           setOf(DomainCreatePermissions
                                                       .getInstance(DomainPermissions
                                                                          .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))));
         fail("checking domain create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void hasDomainCreatePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);
      // setup implicit query permission (=impersonate)
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        DomainCreatePermissions
                                              .getInstance(DomainPermissions
                                                                 .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking domain create permissions with implicit query authorization should have succeeded");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                        setOf(DomainCreatePermissions
                                                    .getInstance(DomainPermissions
                                                                       .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
         fail("checking domain create permissions with implicit query authorization should have succeeded");
      }
   }

   @Test
   public void hasDomainCreatePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      // setup query permission
      grantQueryPermission(authenticatableResource, accessorResource);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions
                                                                    .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)))) {
         fail("checking domain create permissions with query authorization should have succeeded");
      }

      if (!accessControlContext
            .hasDomainCreatePermissions(accessorResource,
                                           setOf(DomainCreatePermissions
                                                       .getInstance(DomainPermissions
                                                                          .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN))))) {
         fail("checking domain create permissions with query authorization should have succeeded");
      }
   }

   @Test
   public void hasDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      try {
         accessControlContext.hasDomainCreatePermissions((Resource) null, domainCreatePermission);
         fail("checking domain create permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(Resources.getInstance(null), domainCreatePermission);
         fail("checking domain create permission with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, (DomainCreatePermission) null);
         fail("checking domain create permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain create permission required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, null, domainCreatePermission);
         fail("checking domain create permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain create permission required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                         domainCreatePermission,
                                                         new DomainCreatePermission[] {null});
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
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence of"));
      }

      // test set-based versions
      try {
         accessControlContext.hasDomainCreatePermissions((Resource) null, setOf(domainCreatePermission));
         fail("checking domain create permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(Resources.getInstance(null), setOf(domainCreatePermission));
         fail("checking domain create permission with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, (Set<DomainCreatePermission>) null);
         fail("checking domain create permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                         setOf(domainCreatePermission, null));
         fail("checking domain create permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void hasDomainCreatePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource, Collections.<DomainCreatePermission>emptySet());
         fail("checking domain create permission with null permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void hasDomainCreatePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      //setup
      grantDomainCreatePermission(accessorResource);

      //verify
      if (!accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                           domainCreatePermission)) {
         fail("checking domain create permission with empty permission sequence should have succeeded");
      }
      if (!accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                           domainCreatePermission,
                                                           new DomainCreatePermission[]{})) {
         fail("checking domain create permission with empty permission sequence should have suceeded");
      }

      if (!accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                           setOf(domainCreatePermission))) {
         fail("checking domain create permission with empty permission sequence should have succeeded");
      }
   }

   @Test
   public void hasDomainCreatePermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      //setup
      grantDomainCreatePermission(accessorResource);

      //verify
      try {
         accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                              domainCreatePermission,
                                                              domainCreatePermission);
         fail("checking domain create permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void hasDomainCreatePermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainCreatePermission domainCreatePermission
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domainCreatePermission_grantable
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);

      //setup
      systemAccessControlContext.setDomainCreatePermissions(accessorResource,
                                                            setOf(domainCreatePermission_grantable));

      //verify
      if (!accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                           domainCreatePermission,
                                                           domainCreatePermission_grantable)) {
         fail("checking domain create permission with duplicate permissions (with different grant options) should have succeeded");
      }

      if (!accessControlContext.hasDomainCreatePermissions(accessorResource,
                                                           setOf(domainCreatePermission,
                                                                 domainCreatePermission_grantable))) {
         fail("checking domain create permission with duplicate permissions (with different grant options) should have succeeded");
      }
   }

   @Test
   public void hasDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);

      try {
         accessControlContext.hasDomainCreatePermissions(invalidResource, domainCreatePermission);
         fail("checking domain create permission with invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(invalidExternalResource, domainCreatePermission);
         fail("checking domain create permission with invalid external resource id should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(mismatchedResource, domainCreatePermission);
         fail("checking domain create permission with mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.hasDomainCreatePermissions(invalidResource, setOf(domainCreatePermission));
         fail("checking domain create permission with invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(invalidExternalResource, setOf(domainCreatePermission));
         fail("checking domain create permission with invalid external resource id should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.hasDomainCreatePermissions(mismatchedResource, setOf(domainCreatePermission));
         fail("checking domain create permission with mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
