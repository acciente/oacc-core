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
package com.acciente.oacc.sql;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

public class SQLProfile implements Serializable {
   private static final long serialVersionUID = 1L;

   public static final SQLProfile DB2_10_5_RECURSIVE;
   public static final SQLProfile DB2_10_5_NON_RECURSIVE;
   public static final SQLProfile Oracle_11_2_RECURSIVE;
   public static final SQLProfile Oracle_11_2_NON_RECURSIVE;
   public static final SQLProfile PostgreSQL_9_3_RECURSIVE;
   public static final SQLProfile PostgreSQL_9_3_NON_RECURSIVE;
   public static final SQLProfile SQLServer_12_0_RECURSIVE;
   public static final SQLProfile SQLServer_12_0_NON_RECURSIVE;
   public static final SQLProfile SQLite_3_8_RECURSIVE;
   public static final SQLProfile SQLite_3_8_NON_RECURSIVE;
   public static final SQLProfile MySQL_5_6_NON_RECURSIVE;
   public static final SQLProfile HSQLDB_2_3_NON_RECURSIVE;

   static {
      DB2_10_5_RECURSIVE = new Builder("DB2_10_5_RECURSIVE")
            .sqlDialect(SQLDialect.DB2_10_5)
            .recursiveCTEEnabled(true)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();

      DB2_10_5_NON_RECURSIVE = new Builder("DB2_10_5_NON_RECURSIVE")
            .sqlDialect(SQLDialect.DB2_10_5)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();

      Oracle_11_2_RECURSIVE = new Builder("Oracle_11_2_RECURSIVE")
            .sqlDialect(SQLDialect.Oracle_11_2)
            .recursiveCTEEnabled(true)
            .recursiveDeleteEnabled(true)
            .sequenceEnabled(true)
            .build();

      Oracle_11_2_NON_RECURSIVE = new Builder("Oracle_11_2_NON_RECURSIVE")
            .sqlDialect(SQLDialect.Oracle_11_2)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();

      PostgreSQL_9_3_RECURSIVE = new Builder("PostgreSQL_9_3_RECURSIVE")
            .sqlDialect(SQLDialect.PostgreSQL_9_3)
            .recursiveCTEEnabled(true)
            .recursiveDeleteEnabled(true)
            .sequenceEnabled(true)
            .build();

      PostgreSQL_9_3_NON_RECURSIVE = new Builder("PostgreSQL_9_3_NON_RECURSIVE")
            .sqlDialect(SQLDialect.PostgreSQL_9_3)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();

      SQLServer_12_0_RECURSIVE = new Builder("SQLServer_12_0_RECURSIVE")
            .sqlDialect(SQLDialect.SQLServer_12_0)
            .recursiveCTEEnabled(true)
            .recursiveDeleteEnabled(true)
            .sequenceEnabled(true)
            .build();

      SQLServer_12_0_NON_RECURSIVE = new Builder("SQLServer_12_0_NON_RECURSIVE")
            .sqlDialect(SQLDialect.SQLServer_12_0)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();

      SQLite_3_8_RECURSIVE = new Builder("SQLite_3_8_RECURSIVE")
            .sqlDialect(SQLDialect.SQLite_3_8)
            .recursiveCTEEnabled(true)
            .recursiveDeleteEnabled(true)
            .sequenceEnabled(false)
            .build();

      SQLite_3_8_NON_RECURSIVE = new Builder("SQLite_3_8_NON_RECURSIVE")
            .sqlDialect(SQLDialect.SQLite_3_8)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(false)
            .build();

      MySQL_5_6_NON_RECURSIVE = new Builder("MySQL_5_6_NON_RECURSIVE")
            .sqlDialect(SQLDialect.MySQL_5_6)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(false)
            .build();

      HSQLDB_2_3_NON_RECURSIVE = new Builder("HSQLDB_2_3_NON_RECURSIVE")
            .sqlDialect(SQLDialect.HSQLDB_2_3)
            .recursiveCTEEnabled(false)
            .recursiveDeleteEnabled(false)
            .sequenceEnabled(true)
            .build();
   }

   public static String nameOf(SQLProfile sqlProfile) {
      return sqlProfile.name;
   }

   public static SQLProfile valueOf(String name) {
      return Builder.valueOf(name);
   }

   // attributes of the SQLProfile
   private final String     name;
   private final SQLDialect sqlDialect;
   private final boolean    recursiveCTEEnabled;
   private final boolean    recursiveDeleteEnabled;
   private final boolean    sequenceEnabled;

   private SQLProfile(Builder builder) {
      this.name = builder.name;
      this.sqlDialect = builder.sqlDialect;
      this.recursiveCTEEnabled = builder.recursiveCTEEnabled;
      this.recursiveDeleteEnabled = builder.recursiveDeleteEnabled;
      this.sequenceEnabled = builder.sequenceEnabled;
   }

   public SQLDialect getSqlDialect() {
      return sqlDialect;
   }

   public boolean isRecursiveCTEEnabled() {
      return recursiveCTEEnabled;
   }

   public boolean isRecursiveDeleteEnabled() {
      return recursiveDeleteEnabled;
   }

   public boolean isSequenceEnabled() {
      return sequenceEnabled;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      SQLProfile that = (SQLProfile) o;

      if (recursiveCTEEnabled != that.recursiveCTEEnabled) {
         return false;
      }
      if (recursiveDeleteEnabled != that.recursiveDeleteEnabled) {
         return false;
      }
      if (sequenceEnabled != that.sequenceEnabled) {
         return false;
      }
      return sqlDialect == that.sqlDialect;
   }

   @Override
   public int hashCode() {
      int result = sqlDialect.hashCode();
      result = 31 * result + (recursiveCTEEnabled ? 1 : 0);
      result = 31 * result + (recursiveDeleteEnabled ? 1 : 0);
      result = 31 * result + (sequenceEnabled ? 1 : 0);
      return result;
   }

   // private builder, also maintains mapping by name
   private static class Builder {
      // a map of all the SQLProfile values defined here keyed by their associated name
      private static final Map<String, SQLProfile> sqlProfilesByName = new LinkedHashMap<>();

      private final String name;

      private SQLDialect sqlDialect;
      private boolean    recursiveCTEEnabled;
      private boolean    recursiveDeleteEnabled;
      private boolean    sequenceEnabled;

      private static SQLProfile valueOf(String name) {
         return sqlProfilesByName.get(name);
      }

      private Builder(String name) {
         this.name = name;
      }

      private Builder sqlDialect(SQLDialect sqlDialect) {
         this.sqlDialect = sqlDialect;
         return this;
      }

      private Builder recursiveCTEEnabled(boolean recursiveCTEEnabled) {
         this.recursiveCTEEnabled = recursiveCTEEnabled;
         return this;
      }

      private Builder recursiveDeleteEnabled(boolean recursiveDeleteEnabled) {
         this.recursiveDeleteEnabled = recursiveDeleteEnabled;
         return this;
      }

      private Builder sequenceEnabled(boolean sequenceEnabled) {
         this.sequenceEnabled = sequenceEnabled;
         return this;
      }

      private SQLProfile build() {
         SQLProfile sqlProfile = new SQLProfile(this);
         sqlProfilesByName.put(name, sqlProfile);
         return sqlProfile;
      }
   }
}
