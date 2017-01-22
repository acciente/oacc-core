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

import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.Resource;
import com.acciente.oacc.ResourceCreatePermissions;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.Resources;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.sql.ResultSet;
import java.sql.SQLException;

public class SQLResult {
   private final ResultSet resultSet;

   SQLResult(ResultSet resultSet) {
      this.resultSet = resultSet;
   }

   public Id<ResourceId> getResourceId(String columnLabel) throws SQLException {
      return Id.from(resultSet.getLong(columnLabel));
   }

   public Resource getResource(String columnLabel) throws SQLException {
      return Resources.getInstance(resultSet.getLong(columnLabel));
   }

   public Resource getResource(String resourceIdColumnLabel, String externalIdColumnLabel) throws SQLException {
      return Resources.getInstance(resultSet.getLong(resourceIdColumnLabel),
                                   resultSet.getString(externalIdColumnLabel));
   }

   public Id<ResourceId> getNextResourceId(int columnIndex) throws SQLException {
      return Id.from(resultSet.getLong(columnIndex));
   }

   public Id<ResourceClassId> getResourceClassId(String columnLabel) throws SQLException {
      return Id.from(resultSet.getLong(columnLabel));
   }

   public Id<DomainId> getResourceDomainId(String columnLabel) throws SQLException {
      return Id.from(resultSet.getLong(columnLabel));
   }

   public Id<ResourcePermissionId> getResourcePermissionId(String columnLabel) throws SQLException {
      return Id.from(resultSet.getLong(columnLabel));
   }

   public String getResourceCreateSysPermissionName(String columnLabel) throws SQLException {
      return ResourceCreatePermissions.getSysPermissionName(resultSet.getLong(columnLabel));
   }

   public String getResourceSysPermissionName(String columnLabel) throws SQLException {
      return ResourcePermissions.getSysPermissionName(resultSet.getLong(columnLabel));
   }

   public String getDomainCreateSysPermissionName(String columnLabel) throws SQLException {
      return DomainCreatePermissions.getSysPermissionName(resultSet.getLong(columnLabel));
   }

   public String getDomainSysPermissionName(String columnLabel) throws SQLException {
      return DomainPermissions.getSysPermissionName(resultSet.getLong(columnLabel));
   }

   public Long getSysPermissionId(String columnLabel) throws SQLException {
      return resultSet.getLong(columnLabel);
   }

   public boolean getBoolean(String columnLabel) throws SQLException {
      return int2bool(resultSet.getInt(columnLabel));
   }

   public int getInteger(String columnLabel) throws SQLException {
      return resultSet.getInt(columnLabel);
   }

   public int getInteger(int columnIndex) throws SQLException {
      return resultSet.getInt(columnIndex);
   }

   public String getString(String columnLabel) throws SQLException {
      return resultSet.getString(columnLabel);
   }

   public boolean next() throws SQLException {
      return resultSet.next();
   }

   public void close() throws SQLException {
      resultSet.close();
   }

   // helpers

   private static boolean int2bool(int value) {
      return value != 0;
   }
}
