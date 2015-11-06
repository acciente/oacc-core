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

public class TestAccessControl_getEffectiveResourcePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final Set<ResourcePermission> resourcePermissions = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourcePermissions_emptyAsAuthenticated() {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Set<ResourcePermission> resourcePermissions = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String accessorExternalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(accessorExternalId);
      final String accessedExternalId = generateUniqueExternalId();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName,
                                                                            generateDomain(),
                                                                            accessedExternalId);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // verify
      Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveResourcePermissions(Resources.getInstance(accessorExternalId),
                                                                   accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      permissions_post
            = accessControlContext.getEffectiveResourcePermissions(accessorResource,
                                                                   Resources.getInstance(accessedExternalId));
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_validAsAuthenticatedResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate new resource
      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDirect() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermissions.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(
            directPermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.addAll(directPermissions);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(expectedPermissions));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(
            inheritResourcePermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.addAll(donorResourcePermissions);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(expectedPermissions));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithMultipleInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource1 = generateUnauthenticatableResource();
      final Resource donorResource2 = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup donor1 permissions
      Set<ResourcePermission> donor1ResourcePermissions = new HashSet<>();
      donor1ResourcePermissions.add(ResourcePermissions.getInstance(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource1, accessedResource, donor1ResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource1, accessedResource), is(donor1ResourcePermissions));

      // setup donor2 permissions
      Set<ResourcePermission> donor2ResourcePermissions = new HashSet<>();
      donor2ResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource2, accessedResource, donor2ResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource2, accessedResource), is(
            donor2ResourcePermissions));

      // inherit from donors
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource1, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource1), is(
            inheritResourcePermissions));

      accessControlContext.setResourcePermissions(accessorResource, donorResource2, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource2), is(inheritResourcePermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.add(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(expectedPermissions));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithGlobal() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDomainInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainInheritedGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, childDomain);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(domainInheritedGlobalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDirectAndInheritedAndGlobalAndDomainInherited() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directPermissionName = generateResourceClassPermission(resourceClassName);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);
      final String directGlobalPermissionName = generateResourceClassPermission(resourceClassName);
      final String domainInheritedGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, childDomain);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermissions.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(inheritedPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, childDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, childDomain), is(globalResourcePermissions));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(directPermissions);
      permissions_expected.addAll(donorResourcePermissions);
      permissions_expected.addAll(globalResourcePermissions);
      permissions_expected.addAll(domainInheritedGlobalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDifferentGrantingRights() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = generateResourceClassPermission(resourceClassName);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, childDomain);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(
            true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermissions.getInstance(permissionName1));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(
            directPermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(permissionName1));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(
            donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(
            inheritResourcePermissions));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(permissionName2));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, childDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            childDomain), is(globalResourcePermissions));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(permissionName2));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            parentDomain), is(
            domainInheritedGlobalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(permissionName1));
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(permissionName2));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_superUser_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource
            = accessControlContext.createResource(authenticatableResourceClassName,
                                                  accessedDomain,
                                                  PasswordCredentials.newInstance(generateUniquePassword()));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // set super-user domain permissions
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessedDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // set direct permissions
      final ResourcePermission customPermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName));

      Set<ResourcePermission> directPermissions = setOf(customPermission);

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // verify
      Set<ResourcePermission> permissions_expected
            = setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.QUERY),
                    ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE),
                    ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS),
                    ResourcePermissions.getInstanceWithGrantOption(customPermission.getPermissionName()));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(
            true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate with query authorization
      generateResourceAndAuthenticate();

      // verify as authenticated resource
      try {
         accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
         fail("getting effective resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getEffectiveResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate with query authorization
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate with query authorization
      generateResourceAndAuthenticate();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      Resource accessedResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourcePermissions(null, accessedResource);
         fail("getting permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(Resources.getInstance(null), accessedResource);
         fail("getting permissions with null internal/external accessor resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourcePermissions(accessorResource, null);
         fail("getting permissions with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(accessedResource, Resources.getInstance(null));
         fail("getting permissions with null internal/external accessed resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
   }

   @Test
   public void getEffectiveResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getEffectiveResourcePermissions(invalidResource, validResource);
         fail("getting effective resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(invalidExternalResource, validResource);
         fail("getting effective resource permissions with invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(mismatchedResource, validResource);
         fail("getting effective resource permissions with mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getEffectiveResourcePermissions(validResource, invalidResource);
         fail("getting effective resource permissions with invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(validResource, invalidExternalResource);
         fail("getting effective resource permissions with invalid external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(validResource, mismatchedResource);
         fail("getting effective resource permissions with mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }
}
