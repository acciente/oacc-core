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

import junit.framework.JUnit4TestAdapter;
import junit.framework.TestSuite;

public class TestAccessControlSuite  {

   public static TestSuite suite() {
      TestSuite suite = new TestSuite();

      suite.addTest(new JUnit4TestAdapter(TestAccessControl_serialize.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_unauthenticatedApiCalls.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_authenticate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_unauthenticate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setCredentials.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createResourceClass.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getDomainDescendants.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createDomain.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createAuthenticatableResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setDomainCreatePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveDomainCreatePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setDomainPermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveDomainPermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setResourceCreatePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveResourceCreatePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setResourcePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveResourcePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setGlobalResourcePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveGlobalResourcePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourcesByResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_assertPostCreateResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourcePermissionNames.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getAccessorResourcesByResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getAuthenticatedResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getSessionResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_assertGlobalResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_assertResourcePermission.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourceClassInfo.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourceClassInfoByResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourceClassNames.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getDomainNameByResource.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_impersonate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_unimpersonate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_authenticateWithCustomAuthenticationProvider.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getDomainCreatePermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getDomainPermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourceCreatePermissions.class));

      return suite;
   }
}
