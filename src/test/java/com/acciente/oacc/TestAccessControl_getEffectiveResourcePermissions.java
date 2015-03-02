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
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(directPermissions));

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
      donorResourcePermissions.add(ResourcePermissions.getInstance(inheritedPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

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
      donor2ResourcePermissions.add(ResourcePermissions.getInstance(inheritedPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource2, accessedResource, donor2ResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource2, accessedResource), is(donor2ResourcePermissions));

      // inherit from donors
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource1, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource1), is(inheritResourcePermissions));

      accessControlContext.setResourcePermissions(accessorResource, donorResource2, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource2), is(inheritResourcePermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.add(ResourcePermissions.getInstance(inheritedPermissionName, true));

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
      donorResourcePermissions.add(ResourcePermissions.getInstance(inheritedPermissionName, true));

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

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermissions.getInstance(permissionName1));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstance(permissionName1, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(permissionName2));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, childDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, childDomain), is(globalResourcePermissions));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermissions.getInstance(permissionName2, true));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain, domainInheritedGlobalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(permissionName1, true));
      permissions_expected.add(ResourcePermissions.getInstance(permissionName2, true));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
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

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourcePermissions(accessorResource, null);
         fail("getting permissions with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
   }

   @Test
   public void getEffectiveResourcePermissions_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final Resource invalidResource = Resources.getInstance(-999L);

      final Set<ResourcePermission> resource1Permissions
            = accessControlContext.getEffectiveResourcePermissions(invalidResource, validResource);
      assertThat(resource1Permissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final Resource invalidResource = Resources.getInstance(-999L);

      try {
         accessControlContext.getEffectiveResourcePermissions(validResource, invalidResource);
         fail("getting effective resource permissions with invalid accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine domain"));
      }
   }
}
