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

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getEffectiveGlobalPermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveGlobalPermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourcePermission> globalResourcePermissionsByClass = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(globalResourcePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalPermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourcePermission> globalResourcePermissionsByClass = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(globalResourcePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalPermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_pre.add(ResourcePermission.getInstance(generateResourceClassPermission(authenticatableResourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_pre,
                                                        sysDomainName);

      // verify
      final Set<ResourcePermission> permissions_post_specific = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_sessionDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalPermissions_validAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
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
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        permissions_pre,
                                                        grantorDomainName);

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, password);

      // verify
      final Set<ResourcePermission> permissions_post_specific = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_sessionDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalPermissions_validInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, sysDomainName);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions on system domain
      Set<ResourcePermission> permissions_parentDomain_pre = new HashSet<>();
      permissions_parentDomain_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true));
      permissions_parentDomain_pre.add(ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD));
      final ResourcePermission resourcePermission_parentDomain = ResourcePermission.getInstance(generateResourceClassPermission(authenticatableResourceClassName));
      permissions_parentDomain_pre.add(resourcePermission_parentDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_parentDomain_pre,
                                                        sysDomainName);

      // setup global permissions on child domain
      Set<ResourcePermission> permissions_childDomain_pre = new HashSet<>();
      permissions_childDomain_pre.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      permissions_childDomain_pre.add(ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD, true));
      final ResourcePermission resourcePermission_childDomain = ResourcePermission.getInstance(generateResourceClassPermission(authenticatableResourceClassName));
      permissions_childDomain_pre.add(resourcePermission_childDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_childDomain_pre,
                                                        childDomainName);

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(permissions_parentDomain_pre);
      permissions_expected.addAll(permissions_childDomain_pre);
      // note that currently grant/non-grantable permissions of the same name do not get squashed into
      // into the grantable version, so you can not expect the following permission set:
      //permissions_expected.add(new Permission(Permission.IMPERSONATE, true));
      //permissions_expected.add(new Permission(Permission.RESET_PASSWORD, true));
      //permissions_expected.add(permission_parentDomain);
      //permissions_expected.add(permission_childDomain);

      final Set<ResourcePermission> permissions_post_sysDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, sysDomainName);
      assertThat(permissions_post_sysDomain, is(permissions_parentDomain_pre));

      final Set<ResourcePermission> permissions_post_childDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, childDomainName);
      assertThat(permissions_post_childDomain, is(permissions_expected));

      final Set<ResourcePermission> permissions_post_sessionDomain = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_parentDomain_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(2));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_parentDomain_pre));
      assertThat(permissions_post_all.get(childDomainName).get(authenticatableResourceClassName), is(permissions_expected));
   }

   @Test
   public void getEffectiveGlobalPermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(null);
         fail("getting create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, null);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      final String resourceClassName = generateResourceClass(false, false);
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, null);
         fail("getting create permissions with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain name must not be null"));
      }
   }
}
