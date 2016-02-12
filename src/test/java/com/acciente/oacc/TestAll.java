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

import com.acciente.oacc.helper.Test_OACC_Resource;
import com.acciente.oacc.sql.TestSQLAccessControlSystemInitializerSuite;
import com.acciente.oacc.sql.TestSchemaNameValidator;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import static org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({Test_OACC_Resource.class,
      TestSQLAccessControlSystemInitializerSuite.class,
      TestSQLAccessControlContextFactory.class,
      TestResourcePermission.class,
      TestResourceCreatePermission.class,
      TestDomainPermission.class,
      TestDomainCreatePermission.class,
      TestSchemaNameValidator.class,
      TestAccessControlSuite.class})
public class TestAll {
}
