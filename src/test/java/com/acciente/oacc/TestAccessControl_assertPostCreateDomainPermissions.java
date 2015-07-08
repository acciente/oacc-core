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

public class TestAccessControl_assertPostCreateDomainPermissions extends TestAccessControlBase {
   @Test
   public void assertPostCreateDomainPermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      // verify setup
      final Set<DomainCreatePermission> allDomainCreatePermissions
            = accessControlContext.getEffectiveDomainCreatePermissions(SYS_RESOURCE);
      assertThat(allDomainCreatePermissions.isEmpty(), is(false));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                           true));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                           true));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                           true),
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                           true));
      // test set-based versions
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      true)));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER,
                                                                                      true)));
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                   DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      true),
                                                                   DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER),
                                                                   DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER,
                                                                                      true)));
   }

   @Test
   public void assertPostCreateDomainPermissions_noPermissions_shouldFailAsAuthenticated() {
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
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting post-create domain permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true));
         fail("asserting multiple post-create domain permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }

      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                setOf(DomainPermissions
                                                                            .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("asserting post-create domain permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                setOf(DomainPermissions
                                                                            .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                      DomainPermissions
                                                                            .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                         true)));
         fail("asserting multiple post-create domain permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate resource without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                DomainPermissions
                                                                      .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting post-create domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                setOf(DomainPermissions
                                                                            .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("asserting post-create domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
   }

   @Test
   public void assertPostCreateDomainPermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate resource with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
   }

   @Test
   public void assertPostCreateDomainPermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
   }

   @Test
   public void assertPostCreateDomainPermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      grantDomainAndChildCreatePermission(accessorResource);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions
                                                                   .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // verify
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true));
         fail("asserting direct and unauthorized post-create domain permission should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }

      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                                    true)));
         fail("asserting direct and unauthorized post-create domain permission should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_multipleDirect_shouldSucceedAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, false),
                    DomainCreatePermissions.getInstance(DomainPermissions
                                                              .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                           false)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                      false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions
                                                                   .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                             DomainPermissions
                                                                   .getInstance(DomainPermissions.SUPER_USER));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                                   DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER)));
   }

   @Test
   public void assertPostCreateDomainPermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // setup create permissions
      Set<DomainCreatePermission> domainCreatePermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE,
                                                        false),
                    DomainCreatePermissions.getInstance(DomainPermissions
                                                              .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                           false)));

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);

      // verify permissions
      final Set<DomainCreatePermission> allDomainCreatePermissions
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(allDomainCreatePermissions, is(domainCreatePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));

      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true));
         fail("asserting post-create domain permission for a direct create permission with exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                setOf(DomainPermissions
                                                                            .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                         true)));
         fail("asserting post-create domain permission for a direct create permission with exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating a domain"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_resourceInherited_succeedsAsAuthenticatedResource() {
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
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
   }

   @Test
   public void assertPostCreateDomainPermissions_superUser_succeedsAsAuthenticatedResource() {
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
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                           true));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions
                                                                   .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions
                                                                   .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                true));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.SUPER_USER,
                                                                                      true)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions
                                                                         .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                      true)));
   }

   @Test
   public void assertPostCreateDomainPermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(
                                                                   accessorPermissionName_createChild,
                                                                   true));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(
                                                                   accessorPermissionName_createChild),
                                                             DomainPermissions.getInstance(
                                                                   accessorPermissionName_createChild,
                                                                   true));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(
                                                                   accessorPermissionName_createChild,
                                                                   true)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(
                                                                         accessorPermissionName_createChild),
                                                                   DomainPermissions.getInstance(
                                                                         accessorPermissionName_createChild,
                                                                         true)));
   }

   @Test
   public void assertPostCreateDomainPermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                           true));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(
                                                                   donorPermissionName_createChild),
                                                             DomainPermissions.getInstance(
                                                                   donorPermissionName_createChild,
                                                                   true));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(
                                                                   donorPermissionName_createChild,
                                                                   true)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(
                                                                         donorPermissionName_createChild),
                                                                   DomainPermissions.getInstance(
                                                                         donorPermissionName_createChild,
                                                                         true)));
   }

   @Test
   public void assertPostCreateDomainPermissions_multiLevelInheritance_shouldSucceedAsAuthorized() {
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
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(donorPermissionName_createChild, true));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(donorPermissionName_createChild),
                                                             DomainPermissions.getInstance(
                                                                   donorPermissionName_createChild,
                                                                   true));

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                                 true)));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(donorPermissionName_createChild),
                                                                   DomainPermissions.getInstance(donorPermissionName_createChild,
                                                                                                 true)));
   }

   @Test
   public void assertPostCreateDomainPermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() {
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

      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             DomainPermissions.getInstance(
                                                                   donorPermissionName_createDomain));
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             setOf(DomainPermissions.getInstance(donorPermissionName_createDomain)));
   }

   @Test
   public void assertPostCreateDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domainPermission2 = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      try {
         accessControlContext.assertPostCreateDomainPermissions((Resource) null, domainPermission);
         fail("asserting post-create domain permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, (DomainPermission) null);
         fail("asserting post-create domain permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, domainPermission, null);
         fail("asserting post-create domain permission with null permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, domainPermission, new DomainPermission[] {null});
         fail("asserting post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                                domainPermission,
                                                                domainPermission2,
                                                                null);
         fail("asserting post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext.assertPostCreateDomainPermissions((Resource) null, setOf(domainPermission));
         fail("asserting post-create domain permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, (Set<DomainPermission>) null);
         fail("asserting post-create domain permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, setOf(domainPermission, null));
         fail("asserting post-create domain permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.assertPostCreateDomainPermissions(accessorResource, Collections.<DomainPermission>emptySet());
         fail("asserting post-create domain permission with null permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // setup permission for accessor
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      setOf(DomainCreatePermissions
                                                                  .getInstance(DomainCreatePermissions.CREATE),
                                                            DomainCreatePermissions.getInstance(domainPermission)));

      // verify
      accessControlContext.assertPostCreateDomainPermissions(accessorResource, domainPermission);
      accessControlContext.assertPostCreateDomainPermissions(accessorResource,
                                                             domainPermission,
                                                             new DomainPermission[]{});
   }

   @Test
   public void assertPostCreateDomainPermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      try {
         accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE, domainPermission, domainPermission);
         fail("asserting post-create domain permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void assertPostCreateDomainPermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainPermission domainPermission
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domainPermission_grantable
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE, domainPermission, domainPermission_grantable);
      accessControlContext.assertPostCreateDomainPermissions(SYS_RESOURCE, setOf(domainPermission, domainPermission_grantable));
   }

   @Test
   public void assertPostCreateDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      try {
         accessControlContext.assertPostCreateDomainPermissions(invalidResource, domainPermission);
         fail("asserting post-create domain permission with invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions(invalidResource, setOf(domainPermission));
         fail("asserting post-create domain permission with invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
   }
}
