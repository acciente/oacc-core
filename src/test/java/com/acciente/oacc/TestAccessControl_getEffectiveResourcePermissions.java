/*
 * Copyright 2009-2014, Acciente LLC
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
   public void getEffectiveResourcePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final Set<ResourcePermission> resourcePermissions = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourcePermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final Set<ResourcePermission> resourcePermissions = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(resourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourcePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      permissions_pre.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_validAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      // authenticate new resource
      generateResourceAndAuthenticate();

      // verify as authenticated resource
      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDirect() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> directPermissions = new HashSet<>();
      directPermissions.add(ResourcePermission.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.addAll(directPermissions);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(expectedPermissions));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithInherited() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String inheritedPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermission.getInstance(inheritedPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // verify
      Set<ResourcePermission> expectedPermissions = new HashSet<>();
      expectedPermissions.addAll(donorResourcePermissions);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(expectedPermissions));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithGlobal() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String directGlobalPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermission.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, globalResourcePermissions, accessedDomain);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDomainInherited() throws AccessControlException {
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
      domainInheritedGlobalResourcePermissions.add(ResourcePermission.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainInheritedGlobalResourcePermissions, parentDomain);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, parentDomain), is(domainInheritedGlobalResourcePermissions));

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(domainInheritedGlobalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithDirectAndInheritedAndGlobalAndDomainInherited() throws AccessControlException {
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
      directPermissions.add(ResourcePermission.getInstance(directPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, directPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(directPermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermission.getInstance(inheritedPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // setup global permissions
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermission.getInstance(directGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, globalResourcePermissions, childDomain);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, childDomain), is(globalResourcePermissions));

      // setup domain-inherited global permissions
      Set<ResourcePermission> domainInheritedGlobalResourcePermissions = new HashSet<>();
      domainInheritedGlobalResourcePermissions.add(ResourcePermission.getInstance(domainInheritedGlobalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainInheritedGlobalResourcePermissions, parentDomain);
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
   public void getEffectiveResourcePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      Resource accessedResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourcePermissions(null, accessedResource);
         fail("getting permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, null);
         fail("getting permissions with null accessed resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
   }
}
