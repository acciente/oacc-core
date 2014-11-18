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
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_emptyAsAuthenticated() throws AccessControlException {
      generateResourceAndAuthenticate();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.isEmpty(), is(true));

      final String resourceClassName = generateResourceClass(false, false);
      final Set<ResourceCreatePermission> resourceCreatePermissionsByClass = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissionsByClass.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> resourceCreatePermissions = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant = ResourceCreatePermission.getInstance(
            ResourceCreatePermission.CREATE,
            true);
      final ResourceCreatePermission createPerm_impersonate = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE), false);
      final ResourceCreatePermission createPerm_inherit_withGrant = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.INHERIT, true), true);
      final ResourceCreatePermission createPerm_resetPwd = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(getSystemResource());
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1, domainName
      );

      final Set<ResourceCreatePermission> resourceCreatePermissions_post = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post2 = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      // get all create permissions and verify for each domain/class combination
      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(createPermissionsByDomainAndClass.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain = createPermissionsByDomainAndClass.get(sysDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(resourceCreatePermissions_pre2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant = ResourceCreatePermission.getInstance(
            ResourceCreatePermission.CREATE,
            true);
      final ResourceCreatePermission createPerm_impersonate = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE), false);
      final ResourceCreatePermission createPerm_inherit_withGrant = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.INHERIT, true), true);
      final ResourceCreatePermission createPerm_resetPwd = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_pre1 = new HashSet<>();
      resourceCreatePermissions_pre1.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_impersonate);
      resourceCreatePermissions_pre1.add(createPerm_inherit_withGrant);
      resourceCreatePermissions_pre1.add(createPerm_resetPwd);

      // set create permissions on custom domain explicitly and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre1, domainName
      );

      // create a new authenticatable 'session' resource
      final char[] password = generateUniquePassword();
      final Resource sessionResource = generateAuthenticatableResource(password);
      final String sessionDomainName = accessControlContext.getDomainNameByResource(sessionResource);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_pre1));

      // set create permissions on session's domain and verify
      Set<ResourceCreatePermission> resourceCreatePermissions_pre2 = new HashSet<>();
      resourceCreatePermissions_pre2.add(createPerm_create_withGrant);
      resourceCreatePermissions_pre2.add(createPerm_resetPwd);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions_pre2, sessionDomainName
      );

      // authenticate the 'session' resource
      accessControlContext.authenticate(sessionResource, PasswordCredentials.newInstance(password));

      // get all create permissions and verify for each domain/resource-class combination
      final Set<ResourceCreatePermission> resourceCreatePermissions_post2 = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(resourceCreatePermissions_post2, is(resourceCreatePermissions_pre2));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsByDomainAndClass = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(createPermissionsByDomainAndClass.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain = createPermissionsByDomainAndClass.get(sessionDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(resourceCreatePermissions_pre2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain = createPermissionsByDomainAndClass.get(domainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(resourceCreatePermissions_pre1));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_validWithInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant = ResourceCreatePermission.getInstance(
            ResourceCreatePermission.CREATE,
            true);
      final ResourceCreatePermission createPerm_impersonate = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE), false);
      final ResourceCreatePermission createPerm_inherit_withGrant = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.INHERIT, true), true);
      final ResourceCreatePermission createPerm_resetPwd = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.RESET_CREDENTIALS, true));
      final ResourceCreatePermission createPerm_resetPwd_withGrant = ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.RESET_CREDENTIALS, true), true);

      final Resource accessorResource = generateUnauthenticatableResource();
      final String parentDomainName = generateDomain();
      final String childDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(childDomainName, parentDomainName);
      final String resourceClassName = generateResourceClass(false, false);

      // set create permissions on parent domain
      Set<ResourceCreatePermission> parentResourceCreatePermissions_pre = new HashSet<>();
      parentResourceCreatePermissions_pre.add(createPerm_create_withGrant);
      parentResourceCreatePermissions_pre.add(createPerm_inherit_withGrant);
      parentResourceCreatePermissions_pre.add(createPerm_resetPwd);
      final ResourcePermission parentResourcePermission_custom = ResourcePermission.getInstance(generateResourceClassPermission(resourceClassName));
      final ResourceCreatePermission parentResourceCreatePermission_custom = ResourceCreatePermission.getInstance(parentResourcePermission_custom, true);
      parentResourceCreatePermissions_pre.add(parentResourceCreatePermission_custom);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentResourceCreatePermissions_pre, parentDomainName
      );

      // set create permissions on child domain
      Set<ResourceCreatePermission> childResourceCreatePermissions_pre = new HashSet<>();
      childResourceCreatePermissions_pre.add(createPerm_create_withGrant);
      childResourceCreatePermissions_pre.add(createPerm_impersonate);
      childResourceCreatePermissions_pre.add(createPerm_resetPwd_withGrant);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        childResourceCreatePermissions_pre, childDomainName
      );

      // verify
      Set<ResourceCreatePermission> childResourceCreatePermissions_expected = new HashSet<>();
      childResourceCreatePermissions_expected.addAll(parentResourceCreatePermissions_pre);
      childResourceCreatePermissions_expected.addAll(childResourceCreatePermissions_pre);

      final Set<ResourceCreatePermission> parentResourceCreatePermissions_post = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, parentDomainName);
      assertThat(parentResourceCreatePermissions_post, is(parentResourceCreatePermissions_pre));

      final Set<ResourceCreatePermission> childResourceCreatePermissions_post = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, childDomainName);
      assertThat(childResourceCreatePermissions_post, is(childResourceCreatePermissions_expected));

      final Map<String, Map<String, Set<ResourceCreatePermission>>> allCreatePermissions = accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
      assertThat(allCreatePermissions.size(), is(2));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_customDomain = allCreatePermissions.get(parentDomainName);
      assertThat(createPermsByResourceClass_customDomain.size(), is(1));
      assertThat(createPermsByResourceClass_customDomain.get(resourceClassName), is(parentResourceCreatePermissions_pre));
      final Map<String, Set<ResourceCreatePermission>> createPermsByResourceClass_sysDomain = allCreatePermissions.get(childDomainName);
      assertThat(createPermsByResourceClass_sysDomain.size(), is(1));
      assertThat(createPermsByResourceClass_sysDomain.get(resourceClassName), is(childResourceCreatePermissions_expected));
   }

   @Test
   public void getEffectiveResourceCreatePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(null);
         fail("getting create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
      }

      final Resource accessorResource = generateUnauthenticatableResource();
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, null);
         fail("getting create permissions with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      final String resourceClassName = generateResourceClass(false, false);
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, null);
         fail("getting create permissions with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain name must not be null"));
      }
   }

   @Test
   public void getEffectiveResourceCreatePermissions_notExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, "invalid_resource_class");
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
