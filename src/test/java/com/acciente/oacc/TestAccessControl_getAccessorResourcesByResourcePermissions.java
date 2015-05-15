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
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getAccessorResourcesByResourcePermissions extends TestAccessControlBase {
   @Test
   public void getAccessorResourcesByResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final String unqueriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> unqueriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(unqueriedPermissionName));

      // set permission between sysresource and accessed
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedResource, unqueriedResourcePermissions);

      // set permission between accessor and accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, unqueriedResourcePermissions);

      // verify
      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_direct_validAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource, unqueriedAccessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedAccessors = setOf(accessorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_direct_validAsAuthorized() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource, unqueriedAccessedResource, resourcePermissions);

      // authenticate and verify
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));
      Set<Resource> expectedAccessors = setOf(accessorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_partialDirect_validAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      final String unqueriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission unqueriedResourcePermission = ResourcePermissions.getInstance(unqueriedPermissionName);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  unqueriedAccessedResource,
                                                  resourcePermissions);

      // verify
      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName),
                                                                             unqueriedResourcePermission);
      assertThat(accessorsByPermission.isEmpty(), is(true));

      Set<Resource> accessorsByReversedPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             unqueriedResourcePermission,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByReversedPermission.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(queriedPermissionName),
                                                                                   unqueriedResourcePermission));
      assertThat(accessorsByPermission2.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_partialDirect_validAsAuthorized() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      final String unqueriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission unqueriedResourcePermission = ResourcePermissions.getInstance(unqueriedPermissionName);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource, unqueriedAccessedResource, resourcePermissions);

      // authenticate and verify
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             unqueriedResourcePermission,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(unqueriedResourcePermission,
                                                                                   ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_multipleDirect_validAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource1 = generateUnauthenticatableResource();
      final Resource accessedResource1 = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource1).getResourceClassName();
      final String queriedPermissionName1 = generateResourceClassPermission(accessedResourceClassName);
      final String queriedPermissionName2 = generateResourceClassPermission(accessedResourceClassName);

      final String unqueriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission unqueriedResourcePermission = ResourcePermissions.getInstance(unqueriedPermissionName);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource1,
                                                  accessedResource1,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName1),
                                                        ResourcePermissions.getInstance(queriedPermissionName2)));

      // set permission between unqueried accessor and queried accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  accessedResource1,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName2)));

      // set permission between unqueried accessor and unqueried accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  unqueriedAccessedResource,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName1),
                                                        ResourcePermissions.getInstance(queriedPermissionName2)));

      // verify
      Set<Resource> expectedAccessors = setOf(accessorResource1);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource1,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName2),
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName1));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource1,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName2),
                                                                                   ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName1)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_multipleDirect_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      final Resource accessorResource1 = generateUnauthenticatableResource();
      final Resource accessedResource1 = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource1).getResourceClassName();
      final String queriedPermissionName1 = generateResourceClassPermission(accessedResourceClassName);
      final String queriedPermissionName2 = generateResourceClassPermission(accessedResourceClassName);

      final String unqueriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission unqueriedResourcePermission = ResourcePermissions.getInstance(unqueriedPermissionName);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource1,
                                                  accessedResource1,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName1),
                                                        ResourcePermissions.getInstance(queriedPermissionName2)));

      // set permission between unqueried accessor and queried accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  accessedResource1,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName2)));

      // set permission between unqueried accessor and unqueried accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  unqueriedAccessedResource,
                                                  setOf(ResourcePermissions.getInstance(queriedPermissionName1),
                                                        ResourcePermissions.getInstance(queriedPermissionName2)));

      // verify
      // authenticate and verify
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));
      Set<Resource> expectedAccessors = setOf(accessorResource1);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource1,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName2),
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName1));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource1,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName2),
                                                                                   ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName1)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_directWithAndWithoutGrant_validAsAuthorized() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String permissionName1 = generateResourceClassPermission(accessedResourceClassName);
      final String permissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission permission1_withGrant = ResourcePermissions.getInstance(permissionName1, true);
      final ResourcePermission permission1_withoutGrant = ResourcePermissions.getInstance(permissionName1);
      final ResourcePermission permission2_withGrant = ResourcePermissions.getInstance(permissionName2, true);
      final ResourcePermission permission2_withoutGrant = ResourcePermissions.getInstance(permissionName2);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(permission1_withoutGrant,
                                                        permission2_withGrant));

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  unqueriedAccessedResource,
                                                  setOf(permission1_withoutGrant));

      // authenticate and verify
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));

      Set<Resource> accessorsByPermission1_withGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission1_withGrant);
      assertThat(accessorsByPermission1_withGrant.isEmpty(), is(true));

      Set<Resource> accessorsByPermission1_withoutGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission1_withoutGrant);
      assertThat(accessorsByPermission1_withoutGrant, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission1_withAndWithoutGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission1_withGrant,
                                                                             permission1_withoutGrant);
      assertThat(accessorsByPermission1_withAndWithoutGrant.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2_withGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission2_withGrant);
      assertThat(accessorsByPermission2_withGrant, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission2_withoutGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission2_withoutGrant);
      assertThat(accessorsByPermission2_withoutGrant, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission2_withAndWithoutGrant
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             permission2_withGrant,
                                                                             permission2_withoutGrant);
      assertThat(accessorsByPermission2_withAndWithoutGrant, is(setOf(accessorResource)));

      // test set-based versions
      Set<Resource> accessorsByPermission1_withGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission1_withGrant));
      assertThat(accessorsByPermission1_withGrant2.isEmpty(), is(true));

      Set<Resource> accessorsByPermission1_withoutGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission1_withoutGrant));
      assertThat(accessorsByPermission1_withoutGrant2, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission1_withAndWithoutGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission1_withGrant,
                                                                                   permission1_withoutGrant));
      assertThat(accessorsByPermission1_withAndWithoutGrant2.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2_withGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission2_withGrant));
      assertThat(accessorsByPermission2_withGrant2, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission2_withoutGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission2_withoutGrant));
      assertThat(accessorsByPermission2_withoutGrant2, is(setOf(accessorResource)));

      Set<Resource> accessorsByPermission2_withAndWithoutGrant2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(permission2_withGrant,
                                                                                   permission2_withoutGrant));
      assertThat(accessorsByPermission2_withAndWithoutGrant2, is(setOf(accessorResource)));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_inherited() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between donor and queried accessed
      accessControlContext.setResourcePermissions(donorResource, accessedResource, resourcePermissions);

      // set inherit permission between accessor and donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // verify
      Set<Resource> expectedAccessors = setOf(donorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_global() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String accessedDomainName = accessControlContext.getDomainNameByResource(accessedResource);
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        accessedResourceClassName,
                                                        accessedDomainName,
                                                        resourcePermissions);

      // verify
      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_superUser() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String accessedDomainName = accessControlContext.getDomainNameByResource(accessedResource);
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);

      // set super-user permission for accessor
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessedDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // verify
      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String accessedResourceClassName_whitespaced = " " + accessedResourceClassName + "\t";
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedAccessors = setOf(accessorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName_whitespaced,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName_whitespaced,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final String queriedPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(null,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        null,
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        (ResourcePermission) null);
         fail("getting accessor resources by resource permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions.getInstance(queriedPermissionName),
                                                                        null);
         fail("getting accessor resources by resource permission with null sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions.getInstance(queriedPermissionName),
                                                                        new ResourcePermission[] {null});
         fail("getting accessor resources by resource permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions.getInstance(queriedPermissionName),
                                                                        ResourcePermissions.getInstance(queriedPermissionName2),
                                                                        null);
         fail("getting accessor resources by resource permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(null,
                                                                        accessedResourceClassName,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName)));
         fail("getting accessor resources by resource permission with null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        null,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName)));
         fail("getting accessor resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        (Set<ResourcePermission>) null);
         fail("getting accessor resources by resource permission with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName),
                                                                              null));
         fail("getting accessor resources by resource permission with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        Collections.<ResourcePermission>emptySet());
         fail("getting accessor resources by resource permission with null permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedAccessors = setOf(accessorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName),
                                                                             new ResourcePermission[] {});
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_duplicates_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName),
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName));
         fail("getting accessor resource by resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_duplicates_shouldSucceed() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName, true));

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedAccessors = setOf(accessorResource);

      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName),
                                                                             ResourcePermissions
                                                                                   .getInstance(queriedPermissionName, true));
      assertThat(accessorsByPermission, is(expectedAccessors));

      Set<Resource> accessorsByPermission2
            = accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                             accessedResourceClassName,
                                                                             setOf(ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName),
                                                                                   ResourcePermissions
                                                                                         .getInstance(
                                                                                               queriedPermissionName,
                                                                                               true)));
      assertThat(accessorsByPermission2, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final Set<ResourcePermission> resourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermissionName));
      final Resource invalidResource = Resources.getInstance(-999L);

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(invalidResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        "does_not_exist",
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions
                                                                              .getInstance("does_not_exist"));
         fail("getting accessor resources by resource permission with non-existent permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        ResourcePermissions
                                                                              .getInstance(queriedPermissionName),
                                                                        ResourcePermissions
                                                                              .getInstance("does_not_exist"));
         fail("getting accessor resources by resource permission with valid and non-existent permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test set-based version
      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(invalidResource,
                                                                        accessedResourceClassName,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName)));
         fail("getting accessor resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        "does_not_exist",
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName)));
         fail("getting accessor resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance("does_not_exist")));
         fail("getting accessor resources by resource permission with non-existent permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource,
                                                                        accessedResourceClassName,
                                                                        setOf(ResourcePermissions
                                                                                    .getInstance(queriedPermissionName),
                                                                              ResourcePermissions
                                                                                    .getInstance("does_not_exist")));
         fail("getting accessor resources by resource permission with valid and non-existent permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
