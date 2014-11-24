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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void setGlobalResourcePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // create dummy domain and class - to check if there were any side-effects later on
      generateDomain();
      generateResourceClass(true, false);

      // set permissions and verify
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_pre.add(ResourcePermission.getInstance(generateResourceClassPermission(authenticatableResourceClassName)));

      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_pre,
                                                        domainName);

      final Set<ResourcePermission> permissions_post_specific = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      // verify no other global permissions were set (i.e. no side-effects)
      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(domainName).size(), is(1));
      assertThat(permissions_post_all.get(domainName).get(authenticatableResourceClassName), is(permissions_pre));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, SYS_RESOURCE).isEmpty(), is(true));
   }

   @Test
   public void setGlobalResourcePermissions_inheritSystemPermission_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));

      // attempt to set *INHERIT system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_pre,
                                                           domainName);
         fail("setting *INHERIT system permission as a global permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid in this context"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_resetPwdPermissionOnUnauthenticatables_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.RESET_CREDENTIALS));

      // attempt to set *RESET_CREDENTIALS system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_pre,
                                                           domainName);
         fail("granting *RESET_CREDENTIALS system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));

      // attempt to set *IMPERSONATE system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_pre,
                                                           domainName);
         fail("granting *IMPERSONATE system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermission.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName,
                                                        grantorResourcePermissions,
                                                        domainName);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set global permissions as grantor and verify
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        permissions_pre,
                                                        domainName);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setGlobalResourcePermissions_validWithDefaultSessionDomain() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermission.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName,
                                                        grantorResourcePermissions,
                                                        grantorDomainName);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, grantorDomainName), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set global permissions as grantor and verify
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(permissions_post, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_explicit = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_explicit, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_accessorDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(permissions_post_accessorDomain.isEmpty(), is(true));
   }


   @Test
   public void setGlobalResourcePermissions_resetPermissions() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre1 = new HashSet<>();
      permissions_pre1.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true));
      permissions_pre1.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        permissions_pre1,
                                                        domainName);

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1, is(permissions_pre1));

      // reset permissions and verify they only contain the latest
      Set<ResourcePermission> permissions_pre2 = new HashSet<>();
      permissions_pre2.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, false));
      permissions_pre2.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));
      assertThat(permissions_pre1, is(not(permissions_pre2)));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        permissions_pre2,
                                                        domainName);

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post2, is(permissions_pre2));

      // reset permissions to empty, i.e. remove all permissions
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        Collections.EMPTY_SET,
                                                        domainName);

      final Set<ResourcePermission> permissions_post3 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setGlobalResourcePermissions_duplicatePermissionNames_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      final String permissionName = generateResourceClassPermission(resourceClassName);
      permissions_pre.add(ResourcePermission.getInstance(permissionName, true));
      permissions_pre.add(ResourcePermission.getInstance(permissionName, false));

      // attempt to set permissions with duplicate permission names
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_pre,
                                                           domainName);
         fail("setting global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_valid = new HashSet<>();
      permissions_valid.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      Set<ResourcePermission> permissions_nullElement = new HashSet<>();
      permissions_nullElement.add(null);

      // attempt to set global permissions with null references
      try {
         accessControlContext.setGlobalResourcePermissions(null, resourceClassName, permissions_valid, domainName);
         fail("setting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, null, permissions_valid, domainName);
         fail("setting permissions for null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, permissions_valid, null);
         fail("setting permissions with null domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain name must not be null"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, null, domainName);
         fail("setting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_nullElement,
                                                           domainName);
         fail("setting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
      }
   }

   @Test
   public void setGlobalResourcePermissions_mismatchedResourceClassAndPermission_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName1)));

      // attempt to set global permissions for mismatched resource class and permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName2,
                                                           permissions_pre,
                                                           domainName);
         fail("setting global permissions with mismatched resource class and permission should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_invalidName = new HashSet<>();
      permissions_invalidName.add(ResourcePermission.getInstance("invalid_permission"));

      Set<ResourcePermission> resourcePermissions_invalidResourceClass = new HashSet<>();
      resourcePermissions_invalidResourceClass.add(ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName)));

      // attempt to set permissions with non-existent references
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, "invalid_resourceClass",
                                                           resourcePermissions_invalidResourceClass,
                                                           domainName);
         fail("setting permissions with non-existent resource class should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_invalidName,
                                                           "invalid_domain");
         fail("setting permissions with non-existent domain should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_invalidName,
                                                           domainName);
         fail("setting permissions with non-existent permission name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not exist for the specified resource class"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_notAuthorized_shouldFail() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_pre.add(ResourcePermission.getInstance(customPermissionName));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(grantorResource).isEmpty(), is(true));

      // attempt to set permissions as grantor without authorization
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                           permissions_pre,
                                                           domainName);
         fail("setting global permissions as grantor without authorization should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }
}
