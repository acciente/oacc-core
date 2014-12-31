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

public class TestAccessControl_getEffectiveResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveResourceCreatePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                    false);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                    true);
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(getSystemResource());
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1,
                                                        domainName
      );

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      // get all create permissions and verify for each domain/class combination
      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(createPermissionsByDomainAndClass.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain
            = createPermissionsByDomainAndClass.get(sysDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(resourceCreatePermissions_pre2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                    false);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                    true);
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1,
                                                        domainName
      );

      // create a new authenticatable 'session' resource
      final char[] password = generateUniquePassword();
      final Resource sessionResource = generateAuthenticatableResource(password);
      final String sessionDomainName = accessControlContext.getDomainNameByResource(sessionResource);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2,
                                                        sessionDomainName
      );

      // authenticate the 'session' resource
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(createPermissionsByDomainAndClass.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain
            = createPermissionsByDomainAndClass.get(sessionDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(resourceCreatePermissions_pre2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validWithInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                    false);
      final ResourceCreatePermission createPerm_inheritGrantable_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                    true);
      final ResourceCreatePermission createPerm_resetPwdGrantable
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
      final ResourceCreatePermission createPerm_resetPwdGrantable_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true),
                                                    true);

      final String parentDomainName = generateDomain();
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, parentDomainName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, childDomainName);
      final String resourceClassName = generateResourceClass(true, false);

      // set create permissions on parent domain
      Set<ResourceCreatePermission> parentResourceCreatePermissions_pre = new HashSet<>();
      parentResourceCreatePermissions_pre.add(createPerm_create_withGrant);
      parentResourceCreatePermissions_pre.add(createPerm_inheritGrantable_withGrant);
      parentResourceCreatePermissions_pre.add(createPerm_resetPwdGrantable);
      final ResourcePermission parentResourcePermission_custom = ResourcePermissions.getInstance(
            generateResourceClassPermission(resourceClassName));
      final ResourceCreatePermission parentResourceCreatePermission_custom = ResourceCreatePermissions.getInstance(
            parentResourcePermission_custom,
            true);
      parentResourceCreatePermissions_pre.add(parentResourceCreatePermission_custom);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentResourceCreatePermissions_pre,
                                                        parentDomainName
      );

      // set create permissions on child domain
      Set<ResourceCreatePermission> childResourceCreatePermissions_pre = new HashSet<>();
      childResourceCreatePermissions_pre.add(createPerm_create_withGrant);
      childResourceCreatePermissions_pre.add(createPerm_impersonate);
      childResourceCreatePermissions_pre.add(createPerm_resetPwdGrantable_withGrant);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        childResourceCreatePermissions_pre,
                                                        childDomainName
      );

      // verify
      Set<ResourceCreatePermission> childResourceCreatePermissions_expected = new HashSet<>();
      childResourceCreatePermissions_expected.add(createPerm_create_withGrant);
      childResourceCreatePermissions_expected.add(createPerm_impersonate);
      childResourceCreatePermissions_expected.add(createPerm_resetPwdGrantable_withGrant);
      childResourceCreatePermissions_expected.add(createPerm_inheritGrantable_withGrant);
      childResourceCreatePermissions_expected.add(parentResourceCreatePermission_custom);

      final Set<ResourceCreatePermission> parentResourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, parentDomainName);
      assertThat(parentResourceCreatePermissions_post, is(parentResourceCreatePermissions_pre));

      final Set<ResourceCreatePermission> childResourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, childDomainName);
      assertThat(childResourceCreatePermissions_post, is(childResourceCreatePermissions_expected));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = allCreatePermissions.get(parentDomainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(parentResourceCreatePermissions_pre));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain
            = allCreatePermissions.get(childDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(childResourceCreatePermissions_expected));

      // authenticate as accesssor resource and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));
      final Set<ResourceCreatePermission> accessorResourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(accessorResourceCreatePermissions_post, is(childResourceCreatePermissions_expected));


   }

   @Test
   public void getEffectiveResourceCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String donorPermissionName_impersonate = ResourcePermissions.IMPERSONATE;
      final String donorPermissionName_resetCredentials = ResourcePermissions.RESET_CREDENTIALS;
      final String accessorPermissionName_impersonate = donorPermissionName_impersonate;
      final String accessorPermissionName_resetCredentials = donorPermissionName_resetCredentials;
      final char[] password = generateUniquePassword();
      final String domainName = generateDomain();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donorPermissions.add(ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true),
                                              true));
      donorPermissions.add(ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, false),
                                              false));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_impersonate, false),
                                                 false));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials, true),
                                                 true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(accessorPermissionName_impersonate, true),
                                                  true));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials, true),
                                                  true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(permissions_expected));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String donorPermissionName_impersonate = ResourcePermissions.IMPERSONATE;
      final String donorPermissionName_resetCredentials = ResourcePermissions.RESET_CREDENTIALS;
      final char[] password = generateUniquePassword();
      final String domainName = generateDomain();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource donor1Resource = generateUnauthenticatableResource();
      final Resource donor2Resource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor 1 domain create permissions
      Set<ResourceCreatePermission> donor1Permissions = new HashSet<>();
      donor1Permissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donor1Permissions.add(ResourceCreatePermissions
                                  .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, false),
                                               true));
      donor1Permissions.add(ResourceCreatePermissions
                                  .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, true),
                                               false));

      accessControlContext.setResourceCreatePermissions(donor1Resource, resourceClass, donor1Permissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donor1Resource, resourceClass, domainName),
                 is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<ResourceCreatePermission> donor2Permissions = new HashSet<>();
      donor2Permissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donor2Permissions.add(ResourceCreatePermissions
                                  .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true),
                                               true));
      donor2Permissions.add(ResourceCreatePermissions
                                  .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, false),
                                               true));

      accessControlContext.setResourceCreatePermissions(donor2Resource, resourceClass, donor2Permissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donor2Resource, resourceClass, domainName),
                 is(donor2Permissions));

      // setup no accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor1
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donor1Resource, accessor2donorPermissions);

      // setup inheritor --INHERIT--> donor2
      accessControlContext.setResourcePermissions(accessorResource, donor2Resource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true),
                                                  true));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, false),
                                                  true));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, true)
                                           , false));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_multiLevelInheritance_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String donorPermissionName_impersonate = ResourcePermissions.IMPERSONATE;
      final String inheritorPermissionName_impersonate = ResourcePermissions.IMPERSONATE;
      final String inheritorPermissionName_resetCredentials = ResourcePermissions.RESET_CREDENTIALS;
      final String accessorPermissionName_resetCredentials = inheritorPermissionName_resetCredentials;
      final char[] password = generateUniquePassword();
      final String domainName = generateDomain();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donorPermissions.add(ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true), true));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup inheritor domain create permissions
      Set<ResourceCreatePermission> inheritorPermissions = new HashSet<>();
      inheritorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      inheritorPermissions.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(inheritorPermissionName_impersonate, false),
                                                  true));
      inheritorPermissions.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(inheritorPermissionName_resetCredentials, true),
                                                  false));

      accessControlContext.setResourceCreatePermissions(inheritorResource, resourceClass, inheritorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(inheritorResource, resourceClass, domainName),
                 is(inheritorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials),
                                                 true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = new HashSet<>();
      inheritor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = new HashSet<>();
      accessor2inheritorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true), true));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials, true),
                                                  false));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials, false),
                                                  true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String donorPermissionName_impersonate = ResourcePermissions.IMPERSONATE;
      final String accessorPermissionName_resetCredentials = ResourcePermissions.RESET_CREDENTIALS;
      final char[] password = generateUniquePassword();
      final String domainName = generateDomain();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource inheritorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate)));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // no inheritor domain create permissions to set up

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials),
                                                 true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> inheritor2donorPermissions = new HashSet<>();
      inheritor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(inheritorResource, donorResource, inheritor2donorPermissions);

      // setup accessor --INHERIT--> inheritor
      Set<ResourcePermission> accessor2inheritorPermissions = new HashSet<>();
      accessor2inheritorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, inheritorResource, accessor2inheritorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials),
                                                  true));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_whitespaceConsistent() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                    false);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                                                    true);
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1,
                                                        domainName
      );

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName_whitespaced,
                                                                         domainName_whitespaced);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName_whitespaced);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(null);
         fail("getting create permissions with null accessor resource should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(null, resourceClassName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(null, resourceClassName, domainName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, null);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, null, domainName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, null);
         fail("getting create permissions with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getEffectiveResourceCreatePermissions_notExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);

      final Set<ResourceCreatePermission> resourceCreatePermissions1
            = accessControlContext.getEffectiveResourceCreatePermissions(invalidResource, resourceClassName);
      assertThat(resourceCreatePermissions1.isEmpty(), is(true));

      final Set<ResourceCreatePermission> resourceCreatePermissions2
            = accessControlContext.getEffectiveResourceCreatePermissions(invalidResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions2.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_notExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, "invalid_resource_class");
         fail("getting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, "invalid_resource_class", domainName);
         fail("getting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      final String resourceClassName = generateResourceClass(false, false);
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, "invalid_resource_domain");
         fail("getting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
