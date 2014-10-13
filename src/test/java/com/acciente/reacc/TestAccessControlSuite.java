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
package com.acciente.reacc;

import junit.framework.JUnit4TestAdapter;
import junit.framework.TestSuite;

public class TestAccessControlSuite  {

   public static TestSuite suite() {
      TestSuite suite = new TestSuite();

      suite.addTest(new JUnit4TestAdapter(TestAccessControl_unauthenticatedApiCalls.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_authenticate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_unauthenticate.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setAuthResourcePassword.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createResourceClass.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getDomainDescendants.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createDomain.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_createResourceClassPermission.class));
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
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_setGlobalPermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getEffectiveGlobalPermissions.class));
      suite.addTest(new JUnit4TestAdapter(TestAccessControl_getResourcesByPermission.class));

      return suite;
   }
}
