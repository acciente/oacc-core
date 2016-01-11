/*
 * Copyright 2009-2016, Acciente LLC
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
   public void getEffectiveResourceCreatePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_emptyAsAuthenticated() {
      generateResourceAndAuthenticate();
      final Resource accessorResource = generateUnauthenticatableResource();
      grantQueryPermission(accessControlContext.getSessionResource(), accessorResource);

      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)
      );
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)
      );
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // get all create permissions and verify for each domain/class combination
      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(createPermissionsByDomainAndClass.size(), is(1));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_withExtId() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(Resources.getInstance(externalId),
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // get all create permissions and verify for each domain/class combination
      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(Resources.getInstance(externalId));
      assertThat(createPermissionsByDomainAndClass.size(), is(1));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsAuthenticatedResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

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
                                                        sessionDomainName,
                                                        resourceCreatePermissions_pre2);

      // authenticate the 'session' resource
      grantQueryPermission(sessionResource, accessorResource);
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, sessionDomainName);
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
   public void getEffectiveResourceCreatePermissions_validWithInheritFromParentDomain() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inheritGrantable_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwdGrantable
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));
      final ResourceCreatePermission createPerm_resetPwdGrantable_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions
                                                          .getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
      final ResourcePermission parentResourcePermission_custom
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));
      final ResourceCreatePermission parentResourceCreatePermission_custom
            = ResourceCreatePermissions.getInstanceWithGrantOption(parentResourcePermission_custom);
      parentResourceCreatePermissions_pre.add(parentResourceCreatePermission_custom);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentDomainName,
                                                        parentResourceCreatePermissions_pre);

      // set create permissions on child domain
      Set<ResourceCreatePermission> childResourceCreatePermissions_pre = new HashSet<>();
      childResourceCreatePermissions_pre.add(createPerm_create_withGrant);
      childResourceCreatePermissions_pre.add(createPerm_impersonate);
      childResourceCreatePermissions_pre.add(createPerm_resetPwdGrantable_withGrant);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        childDomainName,
                                                        childResourceCreatePermissions_pre);

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
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         childDomainName);
      assertThat(childResourceCreatePermissions_post, is(childResourceCreatePermissions_expected));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_parentDomain
            = allCreatePermissions.get(parentDomainName);
      assertThat(createPermsByResourceClass_parentDomain.size(), is(1));
      assertThat(createPermsByResourceClass_parentDomain.get(resourceClassName),
                 is(parentResourceCreatePermissions_pre));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_childDomain
            = allCreatePermissions.get(childDomainName);
      assertThat(createPermsByResourceClass_childDomain.size(), is(1));
      assertThat(createPermsByResourceClass_childDomain.get(resourceClassName), is(childResourceCreatePermissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions = new HashSet<>();
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, domainName, donorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, domainName, accessorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_inheritWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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
                                 .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName_impersonate)));
      donorPermissions.add(ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, domainName, donorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_impersonate)));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstanceWithGrantOption(ResourcePermissions
                                                       .getInstanceWithGrantOption(accessorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, domainName, accessorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(
                                           accessorPermissionName_impersonate)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(
                                           accessorPermissionName_resetCredentials)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_inheritFromTwoResourcesWithDifferentGrantingRights_shouldSucceedAsAuthorized() {
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
                                  .getInstanceWithGrantOption(ResourcePermissions.getInstance(donorPermissionName_impersonate)));
      donor1Permissions.add(ResourceCreatePermissions
                                  .getInstance(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(donor1Resource, resourceClass, domainName, donor1Permissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donor1Resource, resourceClass, domainName),
                 is(donor1Permissions));

      // setup donor 2 domain create permissions
      Set<ResourceCreatePermission> donor2Permissions = new HashSet<>();
      donor2Permissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      donor2Permissions.add(ResourceCreatePermissions
                                  .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName_impersonate)));
      donor2Permissions.add(ResourceCreatePermissions
                                  .getInstanceWithGrantOption(ResourcePermissions.getInstance(donorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(donor2Resource, resourceClass, domainName, donor2Permissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donor2Resource, resourceClass, domainName),
                 is(donor2Permissions));

      // setup no accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, domainName, accessorPermissions);
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
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(
                                           donorPermissionName_impersonate)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstance(
                                           donorPermissionName_resetCredentials)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstanceWithGrantOption(
                                           donorPermissionName_resetCredentials)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_multiLevelInheritance_shouldSucceedAsAuthorized() {
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
                                 .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName_impersonate)));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, domainName, donorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup inheritor domain create permissions
      Set<ResourceCreatePermission> inheritorPermissions = new HashSet<>();
      inheritorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      inheritorPermissions.add(ResourceCreatePermissions
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstance(
                                           inheritorPermissionName_impersonate)));
      inheritorPermissions.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstanceWithGrantOption(
                                           inheritorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(inheritorResource, resourceClass, domainName, inheritorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(inheritorResource,
                                                                            resourceClass,
                                                                            domainName),
                 is(inheritorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstanceWithGrantOption(ResourcePermissions
                                                       .getInstance(accessorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, domainName, accessorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClass,
                                                                            domainName),
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
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(
                                           donorPermissionName_impersonate)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstance(ResourcePermissions.getInstanceWithGrantOption(
                                           accessorPermissionName_resetCredentials)));
      permissions_expected.add(ResourceCreatePermissions
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstance(
                                           accessorPermissionName_resetCredentials)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_multiLevelInheritanceWithEmptyIntermediaryLevel_shouldSucceedAsAuthorized() {
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
      donorPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            donorPermissionName_impersonate)));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, domainName, donorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // no inheritor domain create permissions to set up

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions = new HashSet<>();
      accessorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions.add(ResourceCreatePermissions
                                    .getInstanceWithGrantOption(ResourcePermissions
                                                       .getInstance(accessorPermissionName_resetCredentials)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, domainName, accessorPermissions);
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
                                     .getInstanceWithGrantOption(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_superUser_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // set super-user domain permissions
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));


      // setup direct global permissions
      final ResourcePermission customPermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(authenticatableResourceClassName));
      final ResourceCreatePermission customCreatePermission
            = ResourceCreatePermissions.getInstance(customPermission);
      Set<ResourceCreatePermission> createPermissions_direct
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE)),
                    customCreatePermission);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        createPermissions_direct);

      // verify
      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.QUERY)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermission.getPermissionName())));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         authenticatableResourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> permissions_post_all
            = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(domainName).size(), is(2));
      assertThat(permissions_post_all.get(domainName).get(authenticatableResourceClassName), is(permissions_expected));
      assertThat(permissions_post_all.get(domainName).get(accessControlContext
                                                                .getResourceClassInfoByResource(accessorResource)
                                                                .getResourceClassName()),
                 is(setOf(ResourceCreatePermissions
                                .getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                          ResourceCreatePermissions
                                .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE)),
                          ResourceCreatePermissions
                                .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.QUERY)),
                          ResourceCreatePermissions
                                .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)))));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

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
                                                        sessionDomainName,
                                                        resourceCreatePermissions_pre2);

      // authenticate without query authorization
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, sessionDomainName);
         fail("getting effective resource create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
         fail("getting effective resoure create permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getEffectiveResourceCreatePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

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
                                                        sessionDomainName,
                                                        resourceCreatePermissions_pre2);

      // authenticate with implicit query authorization
      accessControlContext.grantResourcePermissions(sessionResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, sessionDomainName);
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
   public void getEffectiveResourceCreatePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

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
                                                        sessionDomainName,
                                                        resourceCreatePermissions_pre2);

      // authenticate with query authorization
      grantQueryPermission(sessionResource, accessorResource);
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, sessionDomainName);
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
   public void getEffectiveResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

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
                                                        domainName,
                                                        resourceCreatePermissions_pre1);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName_whitespaced,
                                                                         domainName_whitespaced);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(null);
         fail("getting create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(Resources.getInstance(null));
         fail("getting create permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(null, resourceClassName, domainName);
         fail("getting create permissions with null resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(Resources.getInstance(null), resourceClassName, domainName);
         fail("getting create permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, null, domainName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, null);
         fail("getting create permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getEffectiveResourceCreatePermissions_notExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(invalidResource);
         fail("getting create-permissions with reference to non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(invalidExternalResource);
         fail("getting create-permissions with reference to non-existent external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(mismatchedResource);
         fail("getting create-permissions with reference to mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(invalidResource, resourceClassName, domainName);
         fail("getting create-permissions with reference to non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(invalidExternalResource, resourceClassName, domainName);
         fail("getting create-permissions with reference to non-existent external resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(mismatchedResource, resourceClassName, domainName);
         fail("getting create-permissions with reference to mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, "invalid_resource_class", domainName);
         fail("getting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, "invalid_resource_domain");
         fail("getting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
