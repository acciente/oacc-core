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
package com.acciente.oacc.sql;

public enum SQLProfile {
   DB2_10_5_RECURSIVE(new NamedParameters()
                            .sqlDialect(SQLDialect.DB2_10_5)
                            .recursionSupported(true)
                            .recursiveDeleteSupported(false)
                            .sequenceSupported(true)),
   DB2_10_5_NON_RECURSIVE(new NamedParameters()
                                .sqlDialect(SQLDialect.DB2_10_5)
                                .recursionSupported(false)
                                .recursiveDeleteSupported(false)
                                .sequenceSupported(true)),
   Oracle_11_2_RECURSIVE(new NamedParameters()
                               .sqlDialect(SQLDialect.Oracle_11_2)
                               .recursionSupported(true)
                               .recursiveDeleteSupported(true)
                               .sequenceSupported(true)),
   Oracle_11_2_NON_RECURSIVE(new NamedParameters()
                                   .sqlDialect(SQLDialect.Oracle_11_2)
                                   .recursionSupported(false)
                                   .recursiveDeleteSupported(false)
                                   .sequenceSupported(true)),
   PostgreSQL_9_3_RECURSIVE(new NamedParameters()
                                  .sqlDialect(SQLDialect.PostgreSQL_9_3)
                                  .recursionSupported(true)
                                  .recursiveDeleteSupported(true)
                                  .sequenceSupported(true)),
   PostgreSQL_9_3_NON_RECURSIVE(new NamedParameters()
                                      .sqlDialect(SQLDialect.PostgreSQL_9_3)
                                      .recursionSupported(false)
                                      .recursiveDeleteSupported(false)
                                      .sequenceSupported(true)),
   SQLServer_12_0_RECURSIVE(new NamedParameters()
                                  .sqlDialect(SQLDialect.SQLServer_12_0)
                                  .recursionSupported(true)
                                  .recursiveDeleteSupported(true)
                                  .sequenceSupported(true)),
   SQLServer_12_0_NON_RECURSIVE(new NamedParameters()
                                      .sqlDialect(SQLDialect.SQLServer_12_0)
                                      .recursionSupported(false)
                                      .recursiveDeleteSupported(false)
                                      .sequenceSupported(true)),
   SQLite_3_8_RECURSIVE(new NamedParameters()
                              .sqlDialect(SQLDialect.SQLite_3_8)
                              .recursionSupported(true)
                              .recursiveDeleteSupported(true)
                              .sequenceSupported(false)),
   SQLite_3_8_NON_RECURSIVE(new NamedParameters()
                                  .sqlDialect(SQLDialect.SQLite_3_8)
                                  .recursionSupported(false)
                                  .recursiveDeleteSupported(false)
                                  .sequenceSupported(false)),
   ;

   SQLProfile(NamedParameters namedParameters) {
      this.sqlDialect = namedParameters.sqlDialect;
      this.recursionSupported = namedParameters.recursionSupported;
      this.recursiveDeleteSupported = namedParameters.recursiveDeleteSupported;
      this.sequenceSupported = namedParameters.sequenceSupported;
   }

   private final SQLDialect sqlDialect;
   private final boolean    recursionSupported;
   private final boolean    recursiveDeleteSupported;
   private final boolean    sequenceSupported;

   public SQLDialect getSqlDialect() {
      return sqlDialect;
   }

   public boolean isRecursionSupported() {
      return recursionSupported;
   }

   public boolean isRecursiveDeleteSupported() {
      return recursiveDeleteSupported;
   }

   public boolean isSequenceSupported() {
      return sequenceSupported;
   }

   // private pseudo-builder helper
   private static class NamedParameters {
      private SQLDialect sqlDialect;
      private boolean    recursionSupported;
      private boolean    recursiveDeleteSupported;
      private boolean    sequenceSupported;

      public NamedParameters sqlDialect(SQLDialect sqlDialect) {
         this.sqlDialect = sqlDialect;
         return this;
      }

      public NamedParameters recursionSupported(boolean isRecursionSupported) {
         this.recursionSupported = isRecursionSupported;
         return this;
      }

      public NamedParameters recursiveDeleteSupported(boolean isRecursiveDeleteSupported) {
         this.recursiveDeleteSupported = isRecursiveDeleteSupported;
         return this;
      }

      public NamedParameters sequenceSupported(boolean isSequenceSupported) {
         this.sequenceSupported = isSequenceSupported;
         return this;
      }
   }
}
