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

public class TestAccessControl_getResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void getResourceCreatePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getResourceCreatePermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getResourceCreatePermissions_validAsSystemResource() throws AccessControlException {
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
      assertThat(accessControlContext.getResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = setOf(createPerm_create_withGrant,
                                                                           createPerm_impersonate,
                                                                           createPerm_inherit_withGrant,
                                                                           createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1,
                                                        domainName
      );

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = setOf(createPerm_create_withGrant,
                                                                           createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      // get all create permissions and verify for each domain/class combination
      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getResourceCreatePermissionsMap(accessorResource);
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
   public void getResourceCreatePermissions_validAsAuthenticatedResource() throws AccessControlException {
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
      assertThat(accessControlContext.getResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = setOf(createPerm_create_withGrant,
                                                                           createPerm_impersonate,
                                                                           createPerm_inherit_withGrant,
                                                                           createPerm_resetPwd);

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
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = setOf(createPerm_create_withGrant,
                                                                           createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2,
                                                        sessionDomainName
      );

      // authenticate the 'session' resource
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass
            = accessControlContext.getResourceCreatePermissionsMap(accessorResource);
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
   public void getResourceCreatePermissions_validWithInheritFromParentDomain() throws AccessControlException {
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
      final ResourcePermission parentResourcePermission_custom
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));
      final ResourceCreatePermission parentResourceCreatePermission_custom
            = ResourceCreatePermissions.getInstance(parentResourcePermission_custom, true);
      Set<ResourceCreatePermission> parentResourceCreatePermissions_pre = setOf(createPerm_create_withGrant,
                                                                                createPerm_inheritGrantable_withGrant,
                                                                                createPerm_resetPwdGrantable,
                                                                                parentResourceCreatePermission_custom);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentResourceCreatePermissions_pre,
                                                        parentDomainName
      );

      // set create permissions on child domain
      Set<ResourceCreatePermission> childResourceCreatePermissions_pre = setOf(createPerm_create_withGrant,
                                                                               createPerm_impersonate,
                                                                               createPerm_resetPwdGrantable_withGrant);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        childResourceCreatePermissions_pre,
                                                        childDomainName
      );

      // verify
      final Set<ResourceCreatePermission> parentResourceCreatePermissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, parentDomainName);
      assertThat(parentResourceCreatePermissions_post, is(parentResourceCreatePermissions_pre));

      final Set<ResourceCreatePermission> childResourceCreatePermissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, childDomainName);
      assertThat(childResourceCreatePermissions_post, is(childResourceCreatePermissions_pre));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions
            = accessControlContext.getResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain
            = allCreatePermissions.get(parentDomainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(parentResourceCreatePermissions_pre));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain
            = allCreatePermissions.get(childDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(childResourceCreatePermissions_pre));

      // authenticate as accesssor resource and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));
      final Set<ResourceCreatePermission> accessorResourceCreatePermissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(accessorResourceCreatePermissions_post, is(childResourceCreatePermissions_pre));


   }

   @Test
   public void getResourceCreatePermissions_inheritSysPermissionWithDifferentGrantingRights_shouldSucceedAsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, domainName);
      final Resource donorResource = generateUnauthenticatableResource();
      final String resourceClass = generateResourceClass(true, false);

      // setup donor domain create permissions
      Set<ResourceCreatePermission> donorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(accessorPermissions));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(accessorPermissions));
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
      Set<ResourceCreatePermission> donorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_impersonate, true),
                                              true),
                    ResourceCreatePermissions
                                 .getInstance(ResourcePermissions.getInstance(donorPermissionName_resetCredentials, false),
                                              false));

      accessControlContext.setResourceCreatePermissions(donorResource, resourceClass, donorPermissions, domainName);
      assertThat(accessControlContext.getResourceCreatePermissions(donorResource, resourceClass, domainName),
                 is(donorPermissions));

      // setup accessor domain create permissions
      Set<ResourceCreatePermission> accessorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_impersonate, false),
                                                 false),
                    ResourceCreatePermissions
                                    .getInstance(ResourcePermissions.getInstance(accessorPermissionName_resetCredentials, true),
                                                 true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClass, accessorPermissions, domainName);
      assertThat(accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass, domainName),
                 is(accessorPermissions));

      // setup inheritor --INHERIT--> donor
      Set<ResourcePermission> accessor2donorPermissions = new HashSet<>();
      accessor2donorPermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, accessor2donorPermissions);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass, domainName);
      assertThat(permissions_post, is(accessorPermissions));

      final Set<ResourceCreatePermission> permissions_post2
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClass);
      assertThat(permissions_post2, is(accessorPermissions));
   }

   @Test
   public void getResourceCreatePermissions_whitespaceConsistent() throws AccessControlException {
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
      assertThat(accessControlContext.getResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = setOf(createPerm_create_withGrant,
                                                                           createPerm_impersonate,
                                                                           createPerm_inherit_withGrant,
                                                                           createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1,
                                                        domainName
      );

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getResourceCreatePermissions(accessorResource,
                                                                resourceClassName_whitespaced,
                                                                domainName_whitespaced);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = setOf(createPerm_create_withGrant,
                                                                           createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2
            = accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName_whitespaced);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));
   }

   @Test
   public void getResourceCreatePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getResourceCreatePermissionsMap(null);
         fail("getting create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      try {
         accessControlContext.getResourceCreatePermissions(null, resourceClassName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.getResourceCreatePermissions(null, resourceClassName, domainName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, null);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, null, domainName);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, null);
         fail("getting create permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void getResourceCreatePermissions_notExistentReferences_shouldSucceed() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);

      final Set<ResourceCreatePermission> resourceCreatePermissions1
            = accessControlContext.getResourceCreatePermissions(invalidResource, resourceClassName);
      assertThat(resourceCreatePermissions1.isEmpty(), is(true));

      final Set<ResourceCreatePermission> resourceCreatePermissions2
            = accessControlContext.getResourceCreatePermissions(invalidResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions2.isEmpty(), is(true));
   }

   @Test
   public void getResourceCreatePermissions_notExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, "invalid_resource_class");
         fail("getting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, "invalid_resource_class", domainName);
         fail("getting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      final String resourceClassName = generateResourceClass(false, false);
      try {
         accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, "invalid_resource_domain");
         fail("getting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
