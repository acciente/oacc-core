/*
 * Copyright 2009-2017, Acciente LLC
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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SQLStatement {
   private final PreparedStatement statement;

   SQLStatement(PreparedStatement statement) {
      this.statement = statement;
   }

   public void setResourceId(int parameterIndex, Id<ResourceId> resourceId) throws SQLException {
      statement.setLong(parameterIndex, resourceId.getValue());
   }

   public void setResourceId(int parameterIndex, Resource resource) throws SQLException {
      statement.setLong(parameterIndex, resource.getId());
   }

   public void setResourceClassId(int parameterIndex, Id<ResourceClassId> id) throws SQLException {
      statement.setLong(parameterIndex, id.getValue());
   }

   public void setResourceDomainId(int parameterIndex, Id<DomainId> id) throws SQLException {
      statement.setLong(parameterIndex, id.getValue());
   }

   public void setResourceCreateSystemPermissionId(int parameterIndex, long resourceCreateSystemPermissionId) throws SQLException {
      statement.setLong(parameterIndex, resourceCreateSystemPermissionId);
   }

   public void setResourceSystemPermissionId(int parameterIndex, long resourceSystemPermissionId) throws SQLException {
      statement.setLong(parameterIndex, resourceSystemPermissionId);
   }

   public void setResourcePermissionId(int parameterIndex,
                                       Id<ResourcePermissionId> resourcePermissionId) throws SQLException {
      statement.setLong(parameterIndex, resourcePermissionId.getValue());
   }

   public void setDomainCreateSystemPermissionId(int parameterIndex, long domainCreateSystemPermissionId) throws SQLException {
      statement.setLong(parameterIndex, domainCreateSystemPermissionId);
   }

   public void setDomainSystemPermissionId(int parameterIndex, long domainSystemPermissionId) throws SQLException {
      statement.setLong(parameterIndex, domainSystemPermissionId);
   }

   public void setBoolean(int parameterIndex, boolean value) throws SQLException {
      statement.setInt(parameterIndex, bool2int(value));
   }

   public void setString(int parameterIndex, String value) throws SQLException {
      statement.setString(parameterIndex, value);
   }

   public void setNull(int parameterIndex, int sqlType) throws SQLException {
      statement.setNull(parameterIndex, sqlType);
   }

   SQLResult executeQuery() throws SQLException {
      return new SQLResult(statement.executeQuery());
   }

   int executeUpdate() throws SQLException {
      return statement.executeUpdate();
   }

   public SQLResult getGeneratedKeys() throws SQLException {
      return new SQLResult(statement.getGeneratedKeys());
   }

   void close() throws SQLException {
      statement.close();
   }

   // helpers

   private static int bool2int(boolean value) {
      return value ? 1 : 0;
   }
}
