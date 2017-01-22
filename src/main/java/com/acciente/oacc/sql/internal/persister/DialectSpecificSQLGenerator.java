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

import com.acciente.oacc.sql.SQLDialect;

class DialectSpecificSQLGenerator {
   private final String withClause;
   private final String unionClause;
   private final String nextSeqValueStatementPrefix;
   private final String nextSeqValueStatementSuffix;
   private final String nextSeqValueFragmentPrefix;
   private final String nextSeqValueFragmentSuffix;

   private static final DialectSpecificSQLGenerator DB2_10_5       = new DialectSpecificSQLGenerator("WITH", "UNION ALL", "VALUES ( NEXT VALUE FOR ", " )", "NEXT VALUE FOR ", "");
   private static final DialectSpecificSQLGenerator Oracle_11_2    = new DialectSpecificSQLGenerator("WITH", "UNION ALL", "SELECT ", ".NEXTVAL FROM DUAL", "", ".NEXTVAL");
   private static final DialectSpecificSQLGenerator PostgreSQL_9_3 = new DialectSpecificSQLGenerator("WITH RECURSIVE", "UNION ALL", "SELECT nextval('", "')", "nextval('", "')");
   private static final DialectSpecificSQLGenerator SQLServer_12_0 = new DialectSpecificSQLGenerator("WITH", "UNION ALL", "SELECT NEXT VALUE FOR ", "", "NEXT VALUE FOR ", "");
   private static final DialectSpecificSQLGenerator SQLite_3_8     = new DialectSpecificSQLGenerator("WITH RECURSIVE", "UNION ALL", null, null, null, null);
   private static final DialectSpecificSQLGenerator MySQL_5_6      = new DialectSpecificSQLGenerator(null, null, null, null, null, null);
   private static final DialectSpecificSQLGenerator HSQLDB_2_3     = new DialectSpecificSQLGenerator(null, null, "VALUES NEXT VALUE FOR ", "", "NEXT VALUE FOR ", "");

   static DialectSpecificSQLGenerator getInstance(SQLDialect sqlDialect) {
      switch (sqlDialect) {
         case DB2_10_5:
            return DB2_10_5;
         case Oracle_11_2:
            return Oracle_11_2;
         case PostgreSQL_9_3:
            return PostgreSQL_9_3;
         case SQLServer_12_0:
            return SQLServer_12_0;
         case SQLite_3_8:
            return SQLite_3_8;
         case MySQL_5_6:
            return MySQL_5_6;
         case HSQLDB_2_3:
            return HSQLDB_2_3;
         default:
            throw new IllegalArgumentException("Unsupported SQL dialect: " + sqlDialect);
      }
   }

   String getWithClause() {
      return withClause;
   }

   String getUnionClause() {
      return unionClause;
   }

   String nextSequenceValueStatement(String qualifiedSequenceName) {
      return nextSeqValueStatementPrefix + qualifiedSequenceName + nextSeqValueStatementSuffix;
   }

   String nextSequenceValueFragment(String qualifiedSequenceName) {
      return nextSeqValueFragmentPrefix + qualifiedSequenceName + nextSeqValueFragmentSuffix;
   }

   // private constructor to force use of constants
   private DialectSpecificSQLGenerator(String withClause,
                      String unionClause,
                      String nextSeqValueStatementPrefix,
                      String nextSeqValueStatementSuffix,
                      String nextSeqValueFragmentPrefix,
                      String nextSeqValueFragmentSuffix) {
      this.withClause = withClause;
      this.unionClause = unionClause;
      this.nextSeqValueStatementPrefix = nextSeqValueStatementPrefix;
      this.nextSeqValueStatementSuffix = nextSeqValueStatementSuffix;
      this.nextSeqValueFragmentPrefix = nextSeqValueFragmentPrefix;
      this.nextSeqValueFragmentSuffix = nextSeqValueFragmentSuffix;
   }
}
