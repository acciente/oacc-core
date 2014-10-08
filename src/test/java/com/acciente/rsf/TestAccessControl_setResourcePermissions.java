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
package com.acciente.rsf;

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setResourcePermissions extends TestAccessControlBase {
   @Test
   public void setResourcePermission_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      permissions_pre.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setResourcePermission_resetPwdPermissionOnUnauthenticatables_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD));

      // attempt to set *RESET_PASSWORD system permission
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("granting *RESET_PASSWORD system permission to an unauthenticatable resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourcePermission_impersonatePermissionOnUnauthenticatables_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));

      // attempt to set *IMPERSONATE system permission
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("granting *IMPERSONATE system permission on an unauthenticatable resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourcePermission_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT, true));
      grantorResourcePermissions.add(ResourcePermission.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, password);

      // set permissions as grantor and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setResourcePermission_resetPermissions() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre1 = new HashSet<>();
      permissions_pre1.add(ResourcePermission.getInstance(ResourcePermission.INHERIT, true));
      permissions_pre1.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre1);

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post1, is(permissions_pre1));

      // reset permissions and verify they only contain the latest
      Set<ResourcePermission> permissions_pre2 = new HashSet<>();
      permissions_pre2.add(ResourcePermission.getInstance(ResourcePermission.INHERIT, false));
      permissions_pre2.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));
      assertThat(permissions_pre1, is(not(permissions_pre2)));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre2);

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post2, is(permissions_pre2));

      // reset permissions to empty, i.e. remove all permissions
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, Collections.EMPTY_SET);

      final Set<ResourcePermission> permissions_post3 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setResourcePermission_duplicatePermissionNames_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      final String permissionName = generateResourceClassPermission(resourceClassName);
      permissions_pre.add(ResourcePermission.getInstance(permissionName, true));
      permissions_pre.add(ResourcePermission.getInstance(permissionName, false));

      // attempt to set permissions with duplicate permission names
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("setting permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));   // todo: sync error message with code, once it is fixed
      }
   }

   @Test
   public void setResourcePermission_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_valid = new HashSet<>();
      permissions_valid.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      Set<ResourcePermission> permissions_nullElement = new HashSet<>();
      permissions_nullElement.add(null);

      // attempt to set permissions with null references
      try {
         accessControlContext.setResourcePermissions(null, accessedResource, permissions_valid);
         fail("setting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, null, permissions_valid);
         fail("setting permissions for null accessed resource should have failed");
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, accessedResource, null);
         fail("setting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, accessedResource, permissions_nullElement);
         fail("setting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
      }
   }

   @Test
   public void setResourcePermission_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_invalidName = new HashSet<>();
      permissions_invalidName.add(ResourcePermission.getInstance("invalid_permission"));

      Set<ResourcePermission> resourcePermissions_mismatchedResourceClass = new HashSet<>();
      resourcePermissions_mismatchedResourceClass.add(ResourcePermission.getInstance(generateResourceClassPermission(generateResourceClass(false, false))));

      // attempt to set permissions with non-existent references
      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     resourcePermissions_mismatchedResourceClass);
         fail("setting permissions with mismatched resource class should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_invalidName);
         fail("setting permissions with non-existent permission name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
   }

   @Test
   public void setResourcePermission_notAuthorized_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());;
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, password);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource).isEmpty(), is(true));

      // attempt to set permissions as grantor without authorization
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("setting permissions as grantor without authorization should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }
}
