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

import com.acciente.oacc.helper.TestConfigLoader;
import com.acciente.oacc.sql.PasswordEncryptor;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import com.acciente.oacc.sql.internal.SQLPasswordAuthenticationProvider;
import org.junit.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestSQLAccessControlContextFactory {
   @Test
   public void getAccessControlContext_invalidSchemaName_shouldFail() throws SQLException {
      final String invalidSchemaName = "oacc.temp;drop database oaccdb;--";

      final DataSource dataSource = TestConfigLoader.getDataSource();
      final Connection connection = dataSource.getConnection();

      try {
         SQLAccessControlContextFactory.getAccessControlContext(dataSource,
                                                                invalidSchemaName,
                                                                null,
                                                                (PasswordEncryptor) null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
      try {
         SQLAccessControlContextFactory.getAccessControlContext(dataSource,
                                                                invalidSchemaName,
                                                                null,
                                                                (SQLPasswordAuthenticationProvider) null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }

      try {
         SQLAccessControlContextFactory.getAccessControlContext(connection,
                                                                invalidSchemaName,
                                                                null,
                                                                (PasswordEncryptor) null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
      try {
         SQLAccessControlContextFactory.getAccessControlContext(connection,
                                                                invalidSchemaName,
                                                                null,
                                                                (SQLPasswordAuthenticationProvider) null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
   }
}
