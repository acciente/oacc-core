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

public class TestAccessControl_getAccessorResourcesByResourcePermission extends TestAccessControlBase {
   @Test
   public void getAccessorResourcesByResourcePermission_emptyAsSystemResource() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_direct_validAsSystemResource() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_direct_validAsAuthorized() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_directWithAndWithoutGrant_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatedResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();
      final String queriedPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission queriedPermission_withGrant = ResourcePermissions.getInstance(queriedPermissionName, true);
      final ResourcePermission queriedPermission_withoutGrant = ResourcePermissions.getInstance(queriedPermissionName);
      final Set<ResourcePermission> resourcePermissions_withoutGrant = setOf(queriedPermission_withoutGrant);

      final Resource unqueriedAccessedResource = accessControlContext.createResource(accessedResourceClassName);
      final Resource unqueriedAccessorResource = generateUnauthenticatableResource();

      // set permission between accessor and queried accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions_withoutGrant);

      // set permission between unqueried accessor and accessed
      accessControlContext.setResourcePermissions(unqueriedAccessorResource,
                                                  unqueriedAccessedResource,
                                                  resourcePermissions_withoutGrant);

      // authenticate and verify
      accessControlContext.authenticate(authenticatedResource, PasswordCredentials.newInstance(password));

      Set<Resource> accessorsByPermission_withGrant
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            queriedPermission_withGrant);
      assertThat(accessorsByPermission_withGrant.isEmpty(), is(true));

      Set<Resource> expectedAccessors = setOf(accessorResource);
      Set<Resource> accessorsByPermission_withoutGrant
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            queriedPermission_withoutGrant);
      assertThat(accessorsByPermission_withoutGrant, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_inherited() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_global() throws AccessControlException {
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
                                                        resourcePermissions,
                                                        accessedDomainName);

      // verify
      Set<Resource> accessorsByPermission
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_superUser() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission.isEmpty(), is(true));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_whitespaceConsistent() throws AccessControlException {
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
            = accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                            accessedResourceClassName_whitespaced,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessorsByPermission, is(expectedAccessors));
   }

   @Test
   public void getAccessorResourcesByResourcePermission_nulls_shouldFail() throws AccessControlException {
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
         accessControlContext.getAccessorResourcesByResourcePermission(null,
                                                                       accessedResourceClassName,
                                                                       ResourcePermissions
                                                                             .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with null accessed resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                       null,
                                                                       ResourcePermissions
                                                                             .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                       accessedResourceClassName,
                                                                       null);
         fail("getting accessor resources by resource permission with null permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
   }

   @Test
   public void getAccessorResourcesByResourcePermission_nonExistentReferences_shouldFail() throws AccessControlException {
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
         accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                       "does_not_exist",
                                                                       ResourcePermissions
                                                                             .getInstance(queriedPermissionName));
         fail("getting accessor resources by resource permission with non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermission(accessedResource,
                                                                       accessedResourceClassName,
                                                                       ResourcePermissions
                                                                             .getInstance("does_not_exist"));
         fail("getting accessor resources by resource permission with non-existent permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void getAccessorResourcesByResourcePermission_nonExistentReferences_shouldSucceed() throws AccessControlException {
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
      Set<Resource> accessors_nonExistentAccessedResource
            = accessControlContext.getAccessorResourcesByResourcePermission(Resources.getInstance(-999L),
                                                                            accessedResourceClassName,
                                                                            ResourcePermissions
                                                                                  .getInstance(queriedPermissionName));
      assertThat(accessors_nonExistentAccessedResource.isEmpty(), is(true));
   }
}
