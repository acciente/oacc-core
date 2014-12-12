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
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getEffectiveGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveGlobalResourcePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourcePermission> globalResourcePermissionsByClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(globalResourcePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourcePermission> globalResourcePermissionsByClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(globalResourcePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            authenticatableResourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_pre,
                                                        sysDomainName);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_sessionDomain
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName,
                                                        grantorResourcePermissions,
                                                        grantorDomainName);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        permissions_pre,
                                                        grantorDomainName);

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Set<ResourcePermission> permissions_post_sessionDomain
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, sysDomainName);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions on system domain
      Set<ResourcePermission> permissions_parentDomain_pre = new HashSet<>();
      permissions_parentDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      permissions_parentDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
      final ResourcePermission resourcePermission_parentDomain = ResourcePermissions.getInstance(
            generateResourceClassPermission(authenticatableResourceClassName));
      permissions_parentDomain_pre.add(resourcePermission_parentDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_parentDomain_pre,
                                                        sysDomainName);

      // setup global permissions on child domain
      Set<ResourcePermission> permissions_childDomain_pre = new HashSet<>();
      permissions_childDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_childDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
      final ResourcePermission resourcePermission_childDomain = ResourcePermissions.getInstance(
            generateResourceClassPermission(authenticatableResourceClassName));
      permissions_childDomain_pre.add(resourcePermission_childDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource, authenticatableResourceClassName,
                                                        permissions_childDomain_pre,
                                                        childDomainName);

      // verify
      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      permissions_expected.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
      permissions_expected.add(resourcePermission_parentDomain);
      permissions_expected.add(resourcePermission_childDomain);

      final Set<ResourcePermission> permissions_post_sysDomain
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         sysDomainName);
      assertThat(permissions_post_sysDomain, is(permissions_parentDomain_pre));

      final Set<ResourcePermission> permissions_post_childDomain
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         childDomainName);
      assertThat(permissions_post_childDomain, is(permissions_expected));

      final Set<ResourcePermission> permissions_post_sessionDomain
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_sessionDomain, is(permissions_parentDomain_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(2));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_parentDomain_pre));
      assertThat(permissions_post_all.get(childDomainName).get(authenticatableResourceClassName), is(permissions_expected));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validWithInheritFromResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final ResourcePermission resPerm_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourcePermission resPerm_impersonate_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true);
      final ResourcePermission resPerm_resetCredentials
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final ResourcePermission resPerm_resetCredentials_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true);

      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password, domainName);

      // set accessor's global permissions
      Set<ResourcePermission> directResourcePermissions_pre = new HashSet<>();
      directResourcePermissions_pre.add(resPerm_impersonate_withGrant);
      directResourcePermissions_pre.add(resPerm_resetCredentials);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        directResourcePermissions_pre,
                                                        domainName);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<ResourcePermission> donorResourcePermissions_pre = new HashSet<>();
      donorResourcePermissions_pre.add(resPerm_impersonate);
      donorResourcePermissions_pre.add(resPerm_resetCredentials_withGrant);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        donorResourcePermissions_pre,
                                                        domainName);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermisions = new HashSet<>();
      inheritanceResourcePermisions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermisions);

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourcePermission> resourcePermissions_expected = new HashSet<>();
      resourcePermissions_expected.add(resPerm_impersonate_withGrant);
      resourcePermissions_expected.add(resPerm_resetCredentials_withGrant);

      final Set<ResourcePermission> resourcePermissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourcePermissions_post, is(resourcePermissions_expected));

      final Set<ResourcePermission> resourcePermissions_post2
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(resourcePermissions_post2, is(resourcePermissions_expected));

      final Map<String, Map<String,Set<ResourcePermission>>> allGlobalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalResourcePermissions.size(), is(1));
      assertThat(allGlobalResourcePermissions.get(domainName).get(resourceClassName), is(resourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(domainName).size(), is(1));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithInheritFromAncestorDomainAndResource() throws AccessControlException {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final ResourcePermission resPerm_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourcePermission resPerm_impersonate_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true);
      final ResourcePermission resPerm_resetCredentials
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final ResourcePermission resPerm_resetCredentials_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password, childDomain);

      // set parent domain global resource permissions
      Set<ResourcePermission> parentResourcePermissions_pre = new HashSet<>();
      parentResourcePermissions_pre.add(resPerm_impersonate);
      parentResourcePermissions_pre.add(resPerm_resetCredentials_withGrant);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentResourcePermissions_pre,
                                                        parentDomain);

      // set child domain global resource permissions
      Set<ResourcePermission> childResourcePermissions_pre = new HashSet<>();
      childResourcePermissions_pre.add(resPerm_resetCredentials);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        childResourcePermissions_pre,
                                                        childDomain);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<ResourcePermission> parentDomainDonorPermissions_pre = new HashSet<>();
      parentDomainDonorPermissions_pre.add(resPerm_impersonate_withGrant);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        parentDomainDonorPermissions_pre,
                                                        parentDomain);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermisions = new HashSet<>();
      inheritanceResourcePermisions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermisions);

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourcePermission> childResourcePermissions_expected = new HashSet<>();
      childResourcePermissions_expected.add(resPerm_impersonate_withGrant);
      childResourcePermissions_expected.add(resPerm_resetCredentials_withGrant);

      Set<ResourcePermission> parentResourcePermissions_expected = new HashSet<>();
      parentResourcePermissions_expected.add(resPerm_impersonate_withGrant);
      parentResourcePermissions_expected.add(resPerm_resetCredentials_withGrant);

      final Set<ResourcePermission> childResourcePermissions_post 
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, childDomain);
      assertThat(childResourcePermissions_post, is(childResourcePermissions_expected));

      final Set<ResourcePermission> sessionResourcePermissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(sessionResourcePermissions_post, is(childResourcePermissions_expected));

      final Map<String, Map<String,Set<ResourcePermission>>> allGlobalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalResourcePermissions.size(), is(2));
      assertThat(allGlobalResourcePermissions.get(parentDomain).get(resourceClassName), is(parentResourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(parentDomain).size(), is(1));
      assertThat(allGlobalResourcePermissions.get(childDomain).get(resourceClassName), is(childResourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(childDomain).size(), is(1));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_nulls_shouldFail() throws AccessControlException {
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

   @Test
   public void getEffectiveGlobalResourcePermissions_nonExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final Resource invalidResource = Resources.getInstance(-999L);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      final Set<ResourcePermission> resourcePermissions1
            = accessControlContext.getEffectiveGlobalResourcePermissions(invalidResource, resourceClassName);
      assertThat(resourcePermissions1.isEmpty(), is(true));

      final Set<ResourcePermission> resourcePermissions2
            = accessControlContext.getEffectiveGlobalResourcePermissions(invalidResource, resourceClassName, domainName);
      assertThat(resourcePermissions2.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(validResource, "invalid_resourceClassName");
         fail("getting effective global resource permissions with invalid accessed resource class reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(validResource, "invalid_resourceClassName", domainName);
         fail("getting effective global resource permissions with invalid accessed resource class reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(validResource, resourceClassName, "invalid_domainName");
         fail("getting effective global resource permissions with invalid domain reference should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
