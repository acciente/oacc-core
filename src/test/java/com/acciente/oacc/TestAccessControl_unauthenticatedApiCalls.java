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

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

public class TestAccessControl_unauthenticatedApiCalls extends TestAccessControlBase {
   @Test
   public void unimpersonate_shouldSucceed() {
      accessControlContext.unimpersonate();
   }

   @Test
   public void unauthenticated_noSetupReqd_shouldFail() {
      // verify authentication state
      try {
         accessControlContext.getAuthenticatedResource();
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getSessionResource();
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // verify impersonate
      try {
         accessControlContext.impersonate(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // verify credentials
      try {
         accessControlContext.setCredentials(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // verify create methods
      try {
         accessControlContext.createResourceClass(null, false, false);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.createResourcePermission(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.createDomain(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.createDomain(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         final String resourceClassName = generateResourceClass(false, false);
         accessControlContext.createResource(resourceClassName, "any_domain_name");
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         final String resourceClassName = generateResourceClass(true, false);
         accessControlContext.createResource(resourceClassName,
                                             "any_domain_name",
                                             PasswordCredentials.newInstance(generateUniquePassword()));
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // verify getters
      try {
         accessControlContext.getDomainCreatePermissions(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveDomainCreatePermissions(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getDomainPermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getDomainPermissions(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getDomainPermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissions(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveDomainPermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getResourceCreatePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourceCreatePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourceCreatePermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveResourceCreatePermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getResourcePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveResourcePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getGlobalResourcePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getGlobalResourcePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getGlobalResourcePermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getEffectiveGlobalResourcePermissionsMap(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions("any_resource_class_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("any_resource_class_name", "any_domain_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("any_resource_class_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissions((Resource) null, "any_resource_class_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(null, "any_resource_class_name", "any_domain_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((Resource) null, "any_resource_class_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getAccessorResourcesByResourcePermissions(null, "any_resource_class_name", null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getDomainNameByResource(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getDomainDescendants(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourceClassInfo(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourceClassInfoByResource(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourceClassNames();
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getResourcePermissionNames(null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // verify setters
      try {
         accessControlContext.setDomainCreatePermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setDomainPermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setDomainPermissions(null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setResourceCreatePermissions(null, null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setGlobalResourcePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setGlobalResourcePermissions(null, null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.setResourcePermissions(null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // asserts
      try {
         accessControlContext.assertPostCreateDomainPermissions((Resource) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertPostCreateDomainPermissions((Resource) null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertDomainPermissions((Resource) null, (String) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertDomainPermissions((Resource) null, null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions((Resource) null,
                                                                  (String) null,
                                                                  (String) null,
                                                                  (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions((Resource) null,
                                                                  (String) null,
                                                                  (String) null,
                                                                  (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions((Resource) null, null, null, null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions((Resource) null, null, null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(null, null, (String) null, null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(null, null, (String) null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertResourceCreatePermissions((Resource) null,
                                                              (String) null,
                                                              (String) null,
                                                              (ResourceCreatePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertResourceCreatePermissions((Resource) null,
                                                              null,
                                                              null,
                                                              (Set<ResourceCreatePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertResourcePermissions((Resource) null,
                                                        (Resource) null,
                                                        (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.assertResourcePermissions((Resource) null,
                                                        (Resource) null,
                                                        (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // grant/revoke

      try {
         accessControlContext.grantDomainCreatePermissions(null, (DomainCreatePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(null, (Set<DomainCreatePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantDomainPermissions((Resource) null, (String) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantDomainPermissions((Resource) null, (String) null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantDomainPermissions((Resource) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantDomainPermissions((Resource) null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(null, null, (String) null, (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantGlobalResourcePermissions(null, null, (String) null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(null, null, (String) null, (ResourceCreatePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(null, null, (String) null, (Set<ResourceCreatePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantResourcePermissions(null, null, (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.grantResourcePermissions(null, null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.revokeDomainCreatePermissions(null, (DomainCreatePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeDomainCreatePermissions(null, (Set<DomainCreatePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeDomainPermissions((Resource) null, (String) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeDomainPermissions(null, (String) null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeDomainPermissions((Resource) null, (DomainPermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeDomainPermissions(null, (Set<DomainPermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(null, null, (String) null, (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(null, null, (String) null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(null, null, (String) null, (ResourceCreatePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(null, null, (String) null, (Set<ResourceCreatePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeResourcePermissions(null, null, (ResourcePermission) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.revokeResourcePermissions(null, null, (Set<ResourcePermission>) null);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
   }

   @Test
   public void unauthenticated_withReqdSetup_shouldFail() {
      // verify authentication state
      try {
         accessControlContext.getAuthenticatedResource();
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
      try {
         accessControlContext.getSessionResource();
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // setup basic scenario
      final String resourceClassName = generateResourceClass(false, false);
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String domainName = generateDomain();

      // need valid resourceClass and domains to test the
      // following method calls from an unauthenticated context
      try {
         accessControlContext.createResource(resourceClassName, domainName);
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.createResource(authenticatableResourceClassName,
                                             domainName,
                                             PasswordCredentials.newInstance("password".toCharArray()));
         fail("operation should have failed from unauthenticated context");
      }
      catch (NotAuthenticatedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }
   }
}
