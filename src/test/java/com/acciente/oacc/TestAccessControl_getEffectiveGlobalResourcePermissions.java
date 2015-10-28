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
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getEffectiveGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveGlobalResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_emptyAsAuthenticated() {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Map<String, Map<String, Set<ResourcePermission>>> allGlobalPermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalPermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      final Set<ResourcePermission> globalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(globalResourcePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validAsSystemResource() {
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
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            authenticatableResourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(Resources.getInstance(externalId),
                                                                         authenticatableResourceClassName,
                                                                         sysDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(Resources.getInstance(externalId));
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validAsAuthenticatedResource() {
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
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validInheritFromParentDomain() {
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
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        sysDomainName,
                                                        permissions_parentDomain_pre);

      // setup global permissions on child domain
      Set<ResourcePermission> permissions_childDomain_pre = new HashSet<>();
      permissions_childDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_childDomain_pre.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
      final ResourcePermission resourcePermission_childDomain = ResourcePermissions.getInstance(
            generateResourceClassPermission(authenticatableResourceClassName));
      permissions_childDomain_pre.add(resourcePermission_childDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        childDomainName,
                                                        permissions_childDomain_pre);

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

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(2));
      assertThat(permissions_post_all.get(sysDomainName).size(), is(1));
      assertThat(permissions_post_all.get(sysDomainName).get(authenticatableResourceClassName), is(permissions_parentDomain_pre));
      assertThat(permissions_post_all.get(childDomainName).get(authenticatableResourceClassName), is(permissions_expected));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_superUser_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // set super-user domain permissions
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));


      // setup direct global permissions
      final ResourcePermission customPermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName));
      Set<ResourcePermission> globalPermissions_direct
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, false),
                    customPermission);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        globalPermissions_direct);

      // verify
      Set<ResourcePermission> permissions_expected
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.QUERY, true),
                    ResourcePermissions.getInstance(ResourcePermissions.DELETE, true),
                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true),
                    ResourcePermissions.getInstance(customPermission.getPermissionName(), true));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(domainName).size(), is(2));
      assertThat(permissions_post_all.get(domainName).get(authenticatableResourceClassName), is(permissions_expected));
      assertThat(permissions_post_all.get(domainName).get(accessControlContext
                                                                .getResourceClassInfoByResource(accessorResource)
                                                                .getResourceClassName()),
                 is(setOf(ResourcePermissions.getInstance(ResourcePermissions.QUERY, true),
                          ResourcePermissions.getInstance(ResourcePermissions.DELETE, true),
                          ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true))));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_validWithInheritFromResource() {
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
                                                        domainName,
                                                        directResourcePermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<ResourcePermission> donorResourcePermissions_pre = new HashSet<>();
      donorResourcePermissions_pre.add(resPerm_impersonate);
      donorResourcePermissions_pre.add(resPerm_resetCredentials_withGrant);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        donorResourcePermissions_pre);

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

      final Map<String, Map<String,Set<ResourcePermission>>> allGlobalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalResourcePermissions.size(), is(1));
      assertThat(allGlobalResourcePermissions.get(domainName).get(resourceClassName), is(resourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(domainName).size(), is(1));
   }

   @Test
   public void getEffectiveResourcePermissions_validWithInheritFromAncestorDomainAndResource() {
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
                                                        parentDomain,
                                                        parentResourcePermissions_pre);

      // set child domain global resource permissions
      Set<ResourcePermission> childResourcePermissions_pre = new HashSet<>();
      childResourcePermissions_pre.add(resPerm_resetCredentials);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        childDomain,
                                                        childResourcePermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<ResourcePermission> parentDomainDonorPermissions_pre = new HashSet<>();
      parentDomainDonorPermissions_pre.add(resPerm_impersonate_withGrant);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        parentDomain,
                                                        parentDomainDonorPermissions_pre);

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

      final Map<String, Map<String,Set<ResourcePermission>>> allGlobalResourcePermissions
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(allGlobalResourcePermissions.size(), is(2));
      assertThat(allGlobalResourcePermissions.get(parentDomain).get(resourceClassName), is(parentResourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(parentDomain).size(), is(1));
      assertThat(allGlobalResourcePermissions.get(childDomain).get(resourceClassName), is(childResourcePermissions_expected));
      assertThat(allGlobalResourcePermissions.get(childDomain).size(), is(1));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate without query authorization
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
         fail("getting effective global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
         fail("getting effective global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }
   @Test
   public void getEffectiveGlobalResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate with implicit query authorization
      accessControlContext.grantResourcePermissions(grantorResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }
   @Test
   public void getEffectiveGlobalResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            grantorDomainName),
                 is(grantorResourcePermissions));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // authenticate with implicit query authorization
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all
            = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).size(), is(1));
      assertThat(permissions_post_all.get(grantorDomainName).get(resourceClassName), is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String domainName_whitespaced = " " + domainName + "\t";
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup global permissions
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            resourceClassName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      // verify
      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         resourceClassName_whitespaced,
                                                                         domainName_whitespaced);
      assertThat(permissions_post_specific, is(permissions_pre));
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(null);
         fail("getting effective global resource permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(Resources.getInstance(null));
         fail("getting effective global resource permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(null, resourceClassName, domainName);
         fail("getting effective global resource permissions with null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(Resources.getInstance(null), resourceClassName, domainName);
         fail("getting effective global resource permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, null, domainName);
         fail("getting effective global resource permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, null);
         fail("getting effective global resource permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getEffectiveGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource validResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(invalidResource);
         fail("getting effective global resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(invalidExternalResource);
         fail("getting effective global resource permissions with invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(mismatchedResource);
         fail("getting effective global resource permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(invalidResource, resourceClassName, domainName);
         fail("getting effective global resource permissions with invalid accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(invalidExternalResource, resourceClassName, domainName);
         fail("getting effective global resource permissions with invalid external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(mismatchedResource, resourceClassName, domainName);
         fail("getting effective global resource permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(validResource, "invalid_resourceClassName", domainName);
         fail("getting effective global resource permissions with invalid accessed resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(validResource, resourceClassName, "invalid_domainName");
         fail("getting effective global resource permissions with invalid domain reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
